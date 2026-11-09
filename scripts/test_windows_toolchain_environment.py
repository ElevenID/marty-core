import subprocess
from types import SimpleNamespace
import unittest

from windows_toolchain_environment import (
    ToolchainEnvironmentError, capture_visual_studio_environment,
    merge_visual_studio_environment, parse_visual_studio_set_output,
    visual_studio_capture_command,
)


def transcript(**extra):
    values = {"PATH": "VS tools", "INCLUDE": "headers", "LIB": "libraries",
              "VCINSTALLDIR": "VC directory", "VSINSTALLDIR": "VS directory",
              "VSCMD_ARG_TGT_ARCH": "x64", **extra}
    return ("\r\n".join(f"{key}={value}" for key, value in values.items())
            + "\r\n").encode("utf-16-le")


class WindowsToolchainEnvironmentTests(unittest.TestCase):
    def test_authoritative_path_replaces_case_aliases_and_keeps_unrelated_values(self):
        actual = merge_visual_studio_environment(
            {"PATH": "old", "Path": "other old", "CUSTOM": " secret = \u96ea "},
            {"Path": "authoritative", "VCINSTALLDIR": "actual VC"})
        self.assertEqual(actual, {"PATH": "authoritative", "CUSTOM": " secret = \u96ea ",
                                  "VCINSTALLDIR": "actual VC"})
        with self.assertRaisesRegex(ToolchainEnvironmentError, "BASE_ALIAS_CONFLICT"):
            merge_visual_studio_environment({"OTHER": "one", "other": "two"}, {})

    def test_full_vs_fields_and_unicode_values_survive(self):
        text = " Cr\u00e8me\u96ea\U0001f680=\u2028 "
        values = parse_visual_studio_set_output(transcript(UNRELATED=text,
                                                            VCTOOLSVERSION="actual toolset"))
        self.assertEqual(values["UNRELATED"], text)
        self.assertEqual(values["VCTOOLSVERSION"], "actual toolset")
        self.assertTrue({"VCINSTALLDIR", "VSINSTALLDIR", "VSCMD_ARG_TGT_ARCH"} <= values.keys())

    def test_malformed_or_ambiguous_output_fails_without_leaking_it(self):
        for raw in (b"\xff", transcript() + "private value\r\n".encode("utf-16-le"),
                    transcript() + "Path=conflicting private value\r\n".encode("utf-16-le"),
                    transcript(VSCMD_ARG_TGT_ARCH="arm64"), b"x" * 131_073):
            with self.assertRaises(ToolchainEnvironmentError) as failure:
                parse_visual_studio_set_output(raw)
            self.assertNotIn("private value", str(failure.exception))
        with self.assertRaisesRegex(ToolchainEnvironmentError, "REQUIRED_FIELD_MISSING"):
            parse_visual_studio_set_output("PATH=one\r\n".encode("utf-16-le"))

    def test_capture_uses_native_unicode_cmd_without_shell_or_raw_receipt(self):
        calls = []
        secret = "inherited credential never logged"
        def runner(command, **kwargs):
            calls.append((command, kwargs))
            return SimpleNamespace(returncode=0, stdout=transcript(CUSTOM=secret), stderr=b"")
        value = capture_visual_studio_environment(
            {"BASE": "unchanged"}, "C:/Windows/System32/cmd.exe",
            "C:/Program Files/VS/VsDevCmd.bat", runner=runner)
        self.assertEqual(value.environment["BASE"], "unchanged")
        self.assertEqual(value.environment["CUSTOM"], secret)
        self.assertNotIn(secret, repr(value))
        self.assertIn('"C:\\Windows\\System32\\cmd.exe" /d /u /v:off /s /c', calls[0][0])
        self.assertFalse(calls[0][1]["shell"])
        self.assertEqual(calls[0][1]["timeout"], 60)

    def test_setup_failure_timeout_and_limits_keep_only_metadata(self):
        secret = b"credential never logged"
        cases = [(7, secret, secret), (0, b"x" * 131_073, secret),
                 (0, transcript(), b"x" * 16_385)]
        for code, stdout, stderr in cases:
            with self.assertRaises(ToolchainEnvironmentError) as failure:
                capture_visual_studio_environment({}, "C:/Windows/cmd.exe", "C:/VS/VsDevCmd.bat",
                    runner=lambda *a, **k: SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr))
            self.assertNotIn(secret.decode(), repr(failure.exception))
            self.assertEqual(failure.exception.stderr_bytes, len(stderr))
        def timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired("private command", 60, output=secret)
        with self.assertRaisesRegex(ToolchainEnvironmentError, "CAPTURE_TIMEOUT"):
            capture_visual_studio_environment({}, "C:/Windows/cmd.exe", "C:/VS/VsDevCmd.bat",
                                              runner=timeout)

    def test_command_paths_cannot_escape_fixed_capture(self):
        for path in ("cmd.exe", "C:/VS/%UNTRUSTED%/cmd.exe", 'C:/VS/"cmd.exe',
                     "//server/share/cmd.exe"):
            with self.assertRaisesRegex(ToolchainEnvironmentError, "TOOL_PATH_INVALID"):
                visual_studio_capture_command(path, "C:/VS/VsDevCmd.bat")


if __name__ == "__main__":
    unittest.main()
