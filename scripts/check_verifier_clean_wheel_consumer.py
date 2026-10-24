#!/usr/bin/env python3
"""Install one locally built verifier wheel in a fresh venv and run its probe.

The install resolver cannot use package indexes. This checks the local wheel,
not public-channel availability or native-code network isolation.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import tempfile
import venv
from pathlib import Path


PROBE = Path(__file__).resolve().with_name("check_verifier_offline_wheel_consumer.py")
IMPORT_CHECK = Path(__file__).resolve().with_name("check_python_wheel_import.py")
FIXTURES = (
    Path(__file__).resolve().parents[1]
    / "marty-verification/tests/fixtures/open_badges"
)
FIXTURE_NAMES = ("ob2_verify_request.json", "ob3_verify_request.json")


def check_wheel(wheel: Path) -> None:
    if (
        not wheel.is_file()
        or not wheel.name.startswith("marty_verification_py-")
        or wheel.suffix != ".whl"
    ):
        raise ValueError(f"expected one local marty-verification-py wheel: {wheel}")


def stage_consumer(directory: Path) -> tuple[Path, Path, Path]:
    """Copy only the probe and vector inputs; execution never uses checkout paths."""
    fixture_dir = directory / "fixtures"
    fixture_dir.mkdir(parents=True)
    for source, target in (
        (IMPORT_CHECK, directory / IMPORT_CHECK.name),
        (PROBE, directory / PROBE.name),
        *((FIXTURES / name, fixture_dir / name) for name in FIXTURE_NAMES),
    ):
        if not source.is_file() or source.is_symlink():
            raise ValueError(f"missing regular verifier consumer input: {source.name}")
        shutil.copyfile(source, target)
    return directory / IMPORT_CHECK.name, directory / PROBE.name, fixture_dir


def run_clean_consumer(wheel: Path) -> None:
    wheel = wheel.resolve(strict=True)
    check_wheel(wheel)
    with tempfile.TemporaryDirectory(prefix="marty-verifier-consumer-") as directory:
        root = Path(directory)
        if root.resolve().is_relative_to(Path(__file__).resolve().parents[1]):
            raise ValueError(
                "verifier consumer directory must be outside the source checkout"
            )
        environment = root / "venv"
        consumer = root / "consumer"
        consumer.mkdir()
        import_check, probe, fixtures = stage_consumer(consumer)
        venv.EnvBuilder(with_pip=True, system_site_packages=False).create(environment)
        python = environment / (
            "Scripts/python.exe" if os.name == "nt" else "bin/python"
        )
        child_env = os.environ.copy()
        child_env.pop("PYTHONPATH", None)
        child_env.pop("PYTHONHOME", None)
        child_env["PYTHONNOUSERSITE"] = "1"
        subprocess.run(
            [
                str(python),
                "-m",
                "pip",
                "--isolated",
                "install",
                "--no-index",
                "--no-cache-dir",
                "--disable-pip-version-check",
                str(wheel),
            ],
            check=True,
            env=child_env,
            cwd=consumer,
        )
        subprocess.run(
            [str(python), "-I", str(import_check), "marty-verification"],
            check=True,
            env=child_env,
            cwd=consumer,
        )
        subprocess.run(
            [str(python), "-I", str(probe), "--fixtures-dir", str(fixtures)],
            check=True,
            env=child_env,
            cwd=consumer,
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("wheel", type=Path)
    args = parser.parse_args()
    run_clean_consumer(args.wheel)
    print(
        "verifier-clean-wheel-consumer: local wheel installed and verified in fresh venv"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
