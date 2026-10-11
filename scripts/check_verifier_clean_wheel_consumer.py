#!/usr/bin/env python3
"""Install one locally built verifier wheel in a fresh venv and run its probe.

The install resolver cannot use package indexes. This checks the local wheel,
not public-channel availability or native-code network isolation.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import tempfile
import venv
from pathlib import Path


PROBE = Path(__file__).resolve().with_name("check_verifier_offline_wheel_consumer.py")
IMPORT_CHECK = Path(__file__).resolve().with_name("check_python_wheel_import.py")


def check_wheel(wheel: Path) -> None:
    if not wheel.is_file() or not wheel.name.startswith("marty_verification_py-") or wheel.suffix != ".whl":
        raise ValueError(f"expected one local marty-verification-py wheel: {wheel}")


def run_clean_consumer(wheel: Path) -> None:
    wheel = wheel.resolve(strict=True)
    check_wheel(wheel)
    with tempfile.TemporaryDirectory(prefix="marty-verifier-consumer-") as directory:
        environment = Path(directory)
        venv.EnvBuilder(with_pip=True, system_site_packages=False).create(environment)
        python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        child_env = os.environ.copy()
        child_env.pop("PYTHONPATH", None)
        child_env.pop("PYTHONHOME", None)
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
        )
        subprocess.run(
            [str(python), str(IMPORT_CHECK), "marty-verification"],
            check=True,
            env=child_env,
        )
        subprocess.run([str(python), str(PROBE)], check=True, env=child_env)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("wheel", type=Path)
    args = parser.parse_args()
    run_clean_consumer(args.wheel)
    print("verifier-clean-wheel-consumer: local wheel installed and verified in fresh venv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
