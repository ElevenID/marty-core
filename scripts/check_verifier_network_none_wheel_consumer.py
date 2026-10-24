#!/usr/bin/env python3
"""Opt-in exact-wheel consumer in a preloaded Linux/x86_64 network-none image.

This is a local proof, not release qualification. Dependencies must already be
available as wheels; neither pip nor Docker may fetch at execution time.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from check_verifier_clean_wheel_consumer import check_wheel, stage_consumer

INNER = Path(__file__).resolve().with_name("check_verifier_network_none_inner.py")
IMAGE_PATTERN = re.compile(
    r"^(?:docker\.io/library/)?python:3\.11-slim@sha256:[0-9a-f]{64}$"
)
INSPECT_TIMEOUT = 15
CONSUMER_TIMEOUT = 300
RUN_LABEL = "dev.elevenid.verifier-network-none-run"


def check_inputs(wheel: Path, wheelhouse: Path, image: str) -> list[Path]:
    check_wheel(wheel)
    if wheel.is_symlink() or not re.search(
        r"-(?:manylinux[^-]*|linux)_x86_64\.whl$", wheel.name
    ):
        raise ValueError("expected a regular Linux/x86_64 verifier wheel")
    if not IMAGE_PATTERN.fullmatch(image):
        raise ValueError("expected digest-pinned python:3.11-slim image")
    if not wheelhouse.is_dir() or wheelhouse.is_symlink():
        raise ValueError("expected a regular dependency wheelhouse directory")
    dependencies = list(wheelhouse.iterdir())
    if any(
        not item.is_file() or item.is_symlink() or item.suffix != ".whl"
        for item in dependencies
    ):
        raise ValueError("wheelhouse must contain only regular wheel files")
    if any(item.name == wheel.name for item in dependencies):
        raise ValueError("dependency wheelhouse duplicates exact verifier wheel")
    if not INNER.is_file() or INNER.is_symlink():
        raise ValueError("missing regular network-none inner probe")
    return dependencies


def check_preloaded_image(image: str) -> None:
    result = subprocess.run(
        ["docker", "image", "inspect", image],
        check=True,
        text=True,
        capture_output=True,
        timeout=INSPECT_TIMEOUT,
    )
    details = json.loads(result.stdout)
    if (
        len(details) != 1
        or details[0].get("Os") != "linux"
        or details[0].get("Architecture") != "amd64"
    ):
        raise RuntimeError("preloaded Python image must be Linux/amd64")


def cleanup_owned_container(name: str, run_id: str) -> None:
    """Only clean up this invocation's uniquely named and labelled container."""
    if (
        not re.fullmatch(r"[0-9a-f]{32}", run_id)
        or name != "marty-verifier-network-none-" + run_id
    ):
        raise RuntimeError("invalid invocation-owned container identity")
    result = subprocess.run(
        ["docker", "container", "inspect", name],
        text=True,
        capture_output=True,
        timeout=INSPECT_TIMEOUT,
        check=False,
    )
    if result.returncode:
        if (
            "no such container" in result.stderr.lower()
            or "no such object" in result.stderr.lower()
        ):
            return
        raise RuntimeError("could not verify network-none container cleanup")
    details = json.loads(result.stdout)
    if (
        len(details) != 1
        or details[0].get("Name") != "/" + name
        or not re.fullmatch(r"[0-9a-f]{64}", details[0].get("Id", ""))
        or details[0].get("Config", {}).get("Labels", {}).get(RUN_LABEL) != run_id
    ):
        raise RuntimeError(
            "refusing cleanup of a container not owned by this invocation"
        )
    subprocess.run(
        ["docker", "container", "rm", "--force", details[0]["Id"]],
        check=True,
        timeout=INSPECT_TIMEOUT,
    )


def staged_fingerprints(consumer: Path) -> list[dict[str, str | int]]:
    records = []
    for path in sorted(consumer.rglob("*")):
        if path.is_symlink():
            raise ValueError("staged consumer must not contain symlinks")
        if path.is_file():
            with path.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            records.append(
                {
                    "path": path.relative_to(consumer).as_posix(),
                    "bytes": path.stat().st_size,
                    "sha256": digest,
                }
            )
    return records


def run_network_none_consumer(wheel: Path, wheelhouse: Path, image: str) -> None:
    dependencies = check_inputs(wheel, wheelhouse, image)
    check_preloaded_image(image)
    with tempfile.TemporaryDirectory(
        prefix="marty-verifier-network-none-"
    ) as directory:
        root = Path(directory).resolve()
        if root.is_relative_to(Path(__file__).resolve().parents[1]):
            raise ValueError("consumer directory must be outside the source checkout")
        consumer = root / "consumer"
        consumer.mkdir()
        stage_consumer(consumer)
        shutil.copyfile(INNER, consumer / INNER.name)
        wheels = consumer / "wheels"
        wheels.mkdir()
        for source in (wheel, *dependencies):
            shutil.copyfile(source, wheels / source.name)
            with (
                source.open("rb") as original,
                (wheels / source.name).open("rb") as staged,
            ):
                if (
                    hashlib.file_digest(original, "sha256").digest()
                    != hashlib.file_digest(staged, "sha256").digest()
                ):
                    raise RuntimeError("wheel input changed while staging")
        fingerprints = staged_fingerprints(consumer)
        run_id = uuid.uuid4().hex
        name = "marty-verifier-network-none-" + run_id
        try:
            subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--name",
                    name,
                    "--label",
                    f"{RUN_LABEL}={run_id}",
                    "--pull",
                    "never",
                    "--platform",
                    "linux/amd64",
                    "--network",
                    "none",
                    "--read-only",
                    "--tmpfs",
                    "/tmp:rw,nosuid,nodev,size=1073741824,mode=1777",
                    "--memory",
                    "1g",
                    "--memory-swap",
                    "1g",
                    "--cpus",
                    "2",
                    "--pids-limit",
                    "128",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--mount",
                    f"type=bind,src={consumer},dst=/input,readonly",
                    "--workdir",
                    "/input",
                    image,
                    "python",
                    "-I",
                    "/input/check_verifier_network_none_inner.py",
                ],
                check=True,
                timeout=CONSUMER_TIMEOUT,
            )
        except BaseException:
            cleanup_owned_container(name, run_id)
            raise
        print(
            json.dumps(
                {
                    "kind": "verifier-network-none-local-proof",
                    "image": image,
                    "inputs": fingerprints,
                    "release_qualified": False,
                },
                sort_keys=True,
            )
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("wheel", type=Path)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    run_network_none_consumer(args.wheel, args.wheelhouse, args.image)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
