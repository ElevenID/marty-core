#!/usr/bin/env python3
"""Validate the exact-main gate and immutable annotated stable-tag handoff."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any


SCHEMA = "elevenid.stable-tag-preparation/v1"
TAG_PATTERN = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
PREPARATION_WORKFLOW = ".github/workflows/prepare-stable-tag.yml"


class StableTagGateError(ValueError):
    """Raised when stable-tag evidence is incomplete or inconsistent."""


class StableTagGatePending(StableTagGateError):
    """Raised while an exact-main workflow is missing or still running."""


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise StableTagGateError(f"{label} must be a JSON object")
    return value


def _load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as error:
        raise StableTagGateError(f"cannot load {label}: {error}") from error


def version_from_tag(tag: str) -> str:
    match = TAG_PATTERN.fullmatch(tag)
    if match is None:
        raise StableTagGateError(f"invalid stable tag: {tag}")
    return ".".join(match.groups())


def workspace_version(repository: Path) -> str:
    try:
        manifest = tomllib.loads((repository / "Cargo.toml").read_text(encoding="utf-8"))
        value = manifest["workspace"]["package"]["version"]
    except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError) as error:
        raise StableTagGateError(f"cannot resolve workspace version: {error}") from error
    if not isinstance(value, str) or not value:
        raise StableTagGateError("workspace version must be a non-empty string")
    return value


def _git(repository: Path, *arguments: str) -> str:
    try:
        return subprocess.run(
            ["git", *arguments],
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except subprocess.CalledProcessError as error:
        raise StableTagGateError(
            f"git {' '.join(arguments)} failed: {error.stderr.strip()}"
        ) from error


def validate_source(repository: Path, tag: str, expected_commit: str) -> None:
    if not SHA_PATTERN.fullmatch(expected_commit):
        raise StableTagGateError("source commit must be a full lowercase SHA")
    version = version_from_tag(tag)
    if workspace_version(repository) != version:
        raise StableTagGateError("workspace version does not match the stable tag")
    head = _git(repository, "rev-parse", "HEAD^{commit}")
    main = _git(repository, "rev-parse", "refs/remotes/origin/main^{commit}")
    if head != expected_commit or main != expected_commit:
        raise StableTagGateError(
            f"source mismatch: HEAD={head}, origin/main={main}, expected={expected_commit}"
        )


def _workflow_runs(payload: Any) -> list[dict[str, Any]]:
    pages = payload if isinstance(payload, list) else [payload]
    runs: list[dict[str, Any]] = []
    for page_index, page_value in enumerate(pages):
        page = _object(page_value, f"workflow-runs page {page_index}")
        page_runs = page.get("workflow_runs")
        if not isinstance(page_runs, list):
            raise StableTagGateError(
                f"workflow-runs page {page_index} has no workflow_runs array"
            )
        for run_index, run_value in enumerate(page_runs):
            runs.append(_object(run_value, f"workflow run {run_index}"))
    return runs


def validate_workflow_runs(
    payload: Any,
    policy: Any,
    expected_commit: str,
    current_run_id: int,
) -> list[dict[str, Any]]:
    document = _object(policy, "stable-tag policy")
    if document.get("schema") != SCHEMA:
        raise StableTagGateError("stable-tag policy schema is invalid")
    required = document.get("required_workflows")
    if not isinstance(required, list) or not required:
        raise StableTagGateError("stable-tag policy requires at least one workflow")

    runs = _workflow_runs(payload)
    accepted: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str]] = set()
    for index, required_value in enumerate(required):
        item = _object(required_value, f"required_workflows[{index}]")
        path = item.get("path")
        event = item.get("event")
        if not isinstance(path, str) or not path:
            raise StableTagGateError(f"required_workflows[{index}].path is invalid")
        if not isinstance(event, str) or not event:
            raise StableTagGateError(f"required_workflows[{index}].event is invalid")
        key = (path, event)
        if key in seen_keys:
            raise StableTagGateError(f"duplicate required workflow: {path} ({event})")
        seen_keys.add(key)

        matches = [
            run
            for run in runs
            if run.get("path") == path
            and run.get("event") == event
            and run.get("head_sha") == expected_commit
            and run.get("id") != current_run_id
        ]
        if not matches:
            raise StableTagGatePending(
                f"required exact-main workflow is missing: {path}"
            )
        latest = max(matches, key=lambda run: int(run.get("id", 0)))
        if latest.get("status") != "completed":
            raise StableTagGatePending(f"required workflow is still pending: {path}")
        if latest.get("conclusion") != "success":
            raise StableTagGateError(
                f"required workflow did not succeed: {path} ({latest.get('conclusion')})"
            )
        accepted.append(
            {
                "path": path,
                "event": event,
                "run_id": latest.get("id"),
                "conclusion": latest.get("conclusion"),
            }
        )
    return accepted


def preparation_evidence(
    repository_name: str,
    tag: str,
    commit: str,
    run_id: int,
    workflows: list[dict[str, Any]],
) -> dict[str, Any]:
    if not repository_name or "/" not in repository_name:
        raise StableTagGateError("repository name must use owner/name form")
    return {
        "schema": SCHEMA,
        "repository": repository_name,
        "tag": tag,
        "source_sha": commit,
        "preparation_run_id": run_id,
        "required_workflows": workflows,
    }


def record_tag(evidence: Any, tag_object: str, peeled_commit: str) -> dict[str, Any]:
    document = _object(evidence, "preparation evidence").copy()
    if document.get("schema") != SCHEMA:
        raise StableTagGateError("preparation evidence schema is invalid")
    if not SHA_PATTERN.fullmatch(tag_object):
        raise StableTagGateError("annotated tag object must be a full lowercase SHA")
    if peeled_commit != document.get("source_sha"):
        raise StableTagGateError("annotated tag does not peel to the prepared source")
    document["tag_object_sha"] = tag_object
    document["peeled_source_sha"] = peeled_commit
    return document


def parse_tag_message(message: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in message.splitlines():
        if ": " not in line:
            continue
        key, value = line.split(": ", 1)
        if key in {"Stable-Tag-Gate", "Preparation-Run", "Source-SHA"}:
            if key in fields:
                raise StableTagGateError(f"duplicate annotated-tag field: {key}")
            fields[key] = value.strip()
    if fields.get("Stable-Tag-Gate") != SCHEMA:
        raise StableTagGateError("annotated tag has no valid stable-tag gate marker")
    return fields


def validate_release_proof(
    repository_name: str,
    tag: str,
    commit: str,
    tag_type: str,
    tag_object: str,
    tag_message: str,
    run_payload: Any,
    evidence: Any,
) -> None:
    version_from_tag(tag)
    if tag_type != "tag":
        raise StableTagGateError("stable release ref must be an annotated tag object")
    if not SHA_PATTERN.fullmatch(commit) or not SHA_PATTERN.fullmatch(tag_object):
        raise StableTagGateError("release tag identity contains an invalid SHA")

    fields = parse_tag_message(tag_message)
    if fields.get("Source-SHA") != commit:
        raise StableTagGateError("annotated tag source marker does not match its peel")
    try:
        message_run_id = int(fields.get("Preparation-Run", ""))
    except ValueError as error:
        raise StableTagGateError("annotated tag preparation run is invalid") from error

    run = _object(run_payload, "preparation run")
    if (
        run.get("id") != message_run_id
        or run.get("path") != PREPARATION_WORKFLOW
        or run.get("event") != "workflow_dispatch"
        or run.get("head_sha") != commit
        or run.get("head_branch") != "main"
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
    ):
        raise StableTagGateError("preparation workflow run is not an exact successful main run")

    document = _object(evidence, "preparation evidence")
    expected = {
        "schema": SCHEMA,
        "repository": repository_name,
        "tag": tag,
        "source_sha": commit,
        "preparation_run_id": message_run_id,
        "tag_object_sha": tag_object,
        "peeled_source_sha": commit,
    }
    mismatches = [key for key, value in expected.items() if document.get(key) != value]
    if mismatches:
        raise StableTagGateError(
            "preparation evidence does not match release identity: " + ", ".join(mismatches)
        )
    workflows = document.get("required_workflows")
    if not isinstance(workflows, list) or not workflows:
        raise StableTagGateError("preparation evidence has no required workflow results")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--repository", type=Path, required=True)
    prepare.add_argument("--repository-name", required=True)
    prepare.add_argument("--tag", required=True)
    prepare.add_argument("--commit", required=True)
    prepare.add_argument("--run-id", type=int, required=True)
    prepare.add_argument("--runs-json", type=Path, required=True)
    prepare.add_argument("--policy", type=Path, required=True)
    prepare.add_argument("--evidence", type=Path, required=True)

    check = subparsers.add_parser("check-workflows")
    check.add_argument("--commit", required=True)
    check.add_argument("--run-id", type=int, required=True)
    check.add_argument("--runs-json", type=Path, required=True)
    check.add_argument("--policy", type=Path, required=True)

    record = subparsers.add_parser("record-tag")
    record.add_argument("--evidence", type=Path, required=True)
    record.add_argument("--tag-object", required=True)
    record.add_argument("--peeled-commit", required=True)

    release = subparsers.add_parser("validate-release")
    release.add_argument("--repository-name", required=True)
    release.add_argument("--tag", required=True)
    release.add_argument("--commit", required=True)
    release.add_argument("--tag-type", required=True)
    release.add_argument("--tag-object", required=True)
    release.add_argument("--tag-message", type=Path, required=True)
    release.add_argument("--run-json", type=Path, required=True)
    release.add_argument("--evidence", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "prepare":
            validate_source(args.repository, args.tag, args.commit)
            workflows = validate_workflow_runs(
                _load_json(args.runs_json, "workflow runs"),
                _load_json(args.policy, "stable-tag policy"),
                args.commit,
                args.run_id,
            )
            evidence = preparation_evidence(
                args.repository_name, args.tag, args.commit, args.run_id, workflows
            )
            args.evidence.write_text(
                json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        elif args.command == "check-workflows":
            validate_workflow_runs(
                _load_json(args.runs_json, "workflow runs"),
                _load_json(args.policy, "stable-tag policy"),
                args.commit,
                args.run_id,
            )
        elif args.command == "record-tag":
            evidence = record_tag(
                _load_json(args.evidence, "preparation evidence"),
                args.tag_object,
                args.peeled_commit,
            )
            args.evidence.write_text(
                json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        else:
            validate_release_proof(
                args.repository_name,
                args.tag,
                args.commit,
                args.tag_type,
                args.tag_object,
                args.tag_message.read_text(encoding="utf-8"),
                _load_json(args.run_json, "preparation run"),
                _load_json(args.evidence, "preparation evidence"),
            )
    except StableTagGatePending as error:
        print(f"stable-tag-gate: {error}", file=sys.stderr)
        return 2 if args.command == "check-workflows" else 1
    except (OSError, StableTagGateError) as error:
        print(f"stable-tag-gate: {error}", file=sys.stderr)
        return 1
    print("stable-tag-gate: exact-main preparation evidence is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
