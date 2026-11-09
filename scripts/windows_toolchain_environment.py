"""Capture an x64 VS environment without logging inherited credential values."""
from __future__ import annotations

from dataclasses import dataclass, field
import ntpath
import subprocess
from collections.abc import Mapping


class ToolchainEnvironmentError(RuntimeError):
    def __init__(self, code: str, *, returncode: int | None = None,
                 stdout_bytes: int = 0, stderr_bytes: int = 0):
        super().__init__(code)
        self.code = code
        self.returncode = returncode
        self.stdout_bytes = stdout_bytes
        self.stderr_bytes = stderr_bytes


@dataclass(frozen=True)
class CapturedVisualStudioEnvironment:
    environment: dict[str, str] = field(repr=False)
    stdout_bytes: int
    stderr_bytes: int
    returncode: int = 0


def merge_visual_studio_environment(base: Mapping[str, str],
                                    captured: Mapping[str, str]) -> dict[str, str]:
    """Retain unrelated values and replace aliases with the authoritative VS key."""
    result: dict[str, str] = {}
    conflicts: set[str] = set()
    for source in (base, captured):
        for name, value in source.items():
            if not isinstance(name, str) or not name or "=" in name or "\0" in name:
                raise ToolchainEnvironmentError("VS_ENV_NAME_INVALID")
            if not isinstance(value, str) or "\0" in value:
                raise ToolchainEnvironmentError("VS_ENV_VALUE_INVALID")
            key = name.upper()
            if source is base and key in result and result[key] != value:
                conflicts.add(key)
            result[key] = value
        if source is captured:
            conflicts.difference_update(name.upper() for name in captured)
    if conflicts:
        raise ToolchainEnvironmentError("VS_ENV_BASE_ALIAS_CONFLICT")
    return result


def parse_visual_studio_set_output(raw: bytes) -> dict[str, str]:
    if not isinstance(raw, bytes) or len(raw) > 131_072:
        raise ToolchainEnvironmentError("VS_ENV_OUTPUT_LIMIT")
    try:
        text = raw.decode("utf-16-le").removeprefix("\ufeff")
    except UnicodeDecodeError:
        raise ToolchainEnvironmentError("VS_ENV_ENCODING_INVALID") from None
    result: dict[str, str] = {}
    # Only CRLF is a record separator. Unicode value characters stay unchanged.
    for line in text.split("\r\n"):
        if not line or line.startswith("="):  # cmd's internal drive pseudo-vars
            continue
        if "=" not in line or "\r" in line or "\n" in line:
            raise ToolchainEnvironmentError("VS_ENV_RECORD_INVALID")
        name, value = line.split("=", 1)
        key = name.upper()
        if key in result and result[key] != value:
            raise ToolchainEnvironmentError("VS_ENV_CAPTURE_ALIAS_CONFLICT")
        result.update(merge_visual_studio_environment({}, {name: value}))
    for key in ("PATH", "INCLUDE", "LIB", "VCINSTALLDIR", "VSINSTALLDIR",
                "VSCMD_ARG_TGT_ARCH"):
        if not result.get(key):
            raise ToolchainEnvironmentError("VS_ENV_REQUIRED_FIELD_MISSING")
    if result["VSCMD_ARG_TGT_ARCH"] != "x64":
        raise ToolchainEnvironmentError("VS_ENV_TARGET_MISMATCH")
    return result


def visual_studio_capture_command(cmd_path: str, vsdevcmd_path: str) -> str:
    paths = []
    for value in (cmd_path, vsdevcmd_path):
        if (not isinstance(value, str) or not ntpath.isabs(value)
                or len(ntpath.splitdrive(value)[0]) != 2
                or any(char in value for char in ('"', "%", "\0", "\r", "\n"))):
            raise ToolchainEnvironmentError("VS_ENV_TOOL_PATH_INVALID")
        paths.append(ntpath.normpath(value))
    return (f'"{paths[0]}" /d /u /v:off /s /c '
            f'""{paths[1]}" -no_logo -arch=x64 -host_arch=x64 >nul && set"')


def capture_visual_studio_environment(base: Mapping[str, str], cmd_path: str,
                                     vsdevcmd_path: str, *,
                                     runner=subprocess.run) -> CapturedVisualStudioEnvironment:
    """Raw output stays in memory; failures expose only bounded metadata."""
    command = visual_studio_capture_command(cmd_path, vsdevcmd_path)
    try:
        completed = runner(command, env=dict(base), shell=False, capture_output=True,
                           timeout=60,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired:
        raise ToolchainEnvironmentError("VS_ENV_CAPTURE_TIMEOUT") from None
    except OSError:
        raise ToolchainEnvironmentError("VS_ENV_CAPTURE_OS_ERROR") from None
    if not isinstance(completed.stdout, bytes) or not isinstance(completed.stderr, bytes):
        raise ToolchainEnvironmentError("VS_ENV_CAPTURE_OUTPUT_TYPE")
    counts = {"returncode": completed.returncode, "stdout_bytes": len(completed.stdout),
              "stderr_bytes": len(completed.stderr)}
    if len(completed.stdout) > 131_072 or len(completed.stderr) > 16_384:
        raise ToolchainEnvironmentError("VS_ENV_OUTPUT_LIMIT", **counts)
    if type(completed.returncode) is not int or completed.returncode != 0:
        raise ToolchainEnvironmentError("VS_ENV_SETUP_FAILED", **counts)
    captured = parse_visual_studio_set_output(completed.stdout)
    return CapturedVisualStudioEnvironment(
        merge_visual_studio_environment(base, captured), len(completed.stdout),
        len(completed.stderr))
