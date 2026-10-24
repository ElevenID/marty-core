#!/usr/bin/env python3
"""Run staged verifier-wheel checks inside a Linux network-none container."""

from __future__ import annotations

import errno
import os
import platform
import socket
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

PROBE_TIMEOUT = 90


def require_network_none() -> None:
    if sys.platform != "linux" or platform.machine() != "x86_64":
        raise RuntimeError("network-none verifier probe requires Linux/x86_64")
    interfaces = {name for _, name in socket.if_nameindex()}
    if interfaces != {"lo"}:
        raise RuntimeError(f"expected loopback-only network namespace: {interfaces}")
    with socket.socket() as connection:
        connection.settimeout(1)
        try:
            connection.connect(("192.0.2.1", 9))
        except OSError as error:
            if error.errno != errno.ENETUNREACH:
                raise RuntimeError(
                    f"expected no network route, got errno {error.errno}"
                ) from error
        else:
            raise RuntimeError("network negative control unexpectedly connected")


def main() -> int:
    require_network_none()
    consumer = Path(__file__).resolve().parent
    wheelhouse = consumer / "wheels"
    wheels = list(wheelhouse.glob("marty_verification_py-*.whl"))
    if len(wheels) != 1:
        raise RuntimeError("expected exactly one staged verifier wheel")
    with tempfile.TemporaryDirectory(prefix="verifier-network-none-") as directory:
        environment = Path(directory) / "venv"
        venv.EnvBuilder(with_pip=True, system_site_packages=False).create(environment)
        python = environment / "bin/python"
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
                "--find-links",
                str(wheelhouse),
                str(wheels[0]),
            ],
            check=True,
            env=child_env,
            cwd=consumer,
            timeout=PROBE_TIMEOUT,
        )
        subprocess.run(
            [
                str(python),
                "-I",
                str(consumer / "check_python_wheel_import.py"),
                "marty-verification",
            ],
            check=True,
            env=child_env,
            cwd=consumer,
            timeout=PROBE_TIMEOUT,
        )
        subprocess.run(
            [
                str(python),
                "-I",
                str(consumer / "check_verifier_offline_wheel_consumer.py"),
                "--fixtures-dir",
                str(consumer / "fixtures"),
            ],
            check=True,
            env=child_env,
            cwd=consumer,
            timeout=PROBE_TIMEOUT,
        )
    print("verifier-network-none-consumer: local Linux wheel checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
