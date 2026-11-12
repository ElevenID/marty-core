"""Canonical offline stable-tag evidence contract for ElevenID release gates.

Repository adapters retain version, source admission and workflow-result policy.
Consumers must distribute this file from a reviewed immutable Core commit, with
its source SHA and content digest; do not maintain independent implementations.
"""
from __future__ import annotations

import re
from typing import Any

SCHEMA = "elevenid.stable-tag-preparation/v1"
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
PREPARATION_WORKFLOW = ".github/workflows/prepare-stable-tag.yml"

class StableTagGateError(ValueError):
    """Raised when stable-tag evidence is incomplete or inconsistent."""



def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise StableTagGateError(f"{label} must be a JSON object")
    return value



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



def validate_release_identity(
    repository_name: str,
    tag: str,
    commit: str,
    tag_type: str,
    tag_object: str,
    tag_message: str,
    run_payload: Any,
    evidence: Any,
) -> list[dict[str, Any]]:
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

    return workflows
