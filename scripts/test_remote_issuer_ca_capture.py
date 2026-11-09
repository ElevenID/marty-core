"""Exercise the real CA-read loop without Docker or a KMS fixture."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("test_remote_issuer_live_kms.sh")


class CaCaptureTests(unittest.TestCase):
    def run_loop(self, mode, *, existing=False):
        bash = shutil.which("bash")
        if os.name == "nt":
            bash = str(Path(os.environ["ProgramFiles"]) / "Git/bin/bash.exe")
        if not bash or not Path(bash).is_file():
            self.skipTest("Bash is required for the production shell-loop controls")
        source = SCRIPT.read_text(encoding="utf8")
        loop = source.split("last_ca_exec_status=0\n", 1)[1].split(
            "for attempt in {1..30}; do\n  if curl", 1
        )[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sentinel = root / "owned-cid.ca-exec-1.stdout.private"
            if existing:
                sentinel.write_bytes(b"preserve-existing-evidence")
            setup = r"""
set -euo pipefail
cd -- "$1"
ca_cert=ca.tmp
ca_exec_error=error.tmp
name=exact-owned-fixture
MARTY_TEST_OPENBAO_CID_FILE=owned-cid
last_ca_exec_status=0
sleep() { :; }
docker() {
  if [[ "$1" == inspect ]]; then printf 'running 0\n'; return 0; fi
  [[ "$1 $3 $4" == 'exec cat /tmp/certs/vault-ca.pem' ]] || return 90
  if [[ "$2" != "$name" ]]; then return 91; fi
  if [[ "$MODE" == success ]]; then printf 'public-ca'; return 0; fi
  printf '%010000d' 0 | tr '0' 'X'
  if [[ "$MODE" == stderr ]]; then printf 'PRIVATE-EXEC-ERROR' >&2; fi
  return 128
}
"""
            harness = root / "loop.sh"
            harness.write_text(setup + loop, encoding="utf8")
            result = subprocess.run(
                [bash, str(harness), root.as_posix()],
                env={**os.environ, "MODE": mode},
                capture_output=True,
                timeout=20,
            )
            files = {p.name: p.read_bytes() for p in root.glob("*.private")}
        return result, files

    def test_failed_stdout_is_private_bounded_and_all_attempts_remain(self):
        result, files = self.run_loop("stdout")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(len(files), 30)
        self.assertTrue(all(value == b"X" * 4096 for value in files.values()))
        self.assertEqual(result.stdout, b"")
        self.assertNotIn(b"X" * 20, result.stderr)
        self.assertEqual(result.stderr.count(b"execStatus=128"), 30)

    def test_success_does_not_publish_failed_stdout(self):
        result, files = self.run_loop("success")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(files, {})
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr.count(b"execStatus=0"), 1)

    def test_existing_evidence_is_never_overwritten(self):
        result, files = self.run_loop("stdout", existing=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(
            files["owned-cid.ca-exec-1.stdout.private"],
            b"preserve-existing-evidence",
        )
        self.assertEqual(len(files), 1)

    def test_stderr_stays_private_alongside_failed_stdout(self):
        result, files = self.run_loop("stderr")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(len(files), 60)
        self.assertNotIn(b"PRIVATE-EXEC-ERROR", result.stderr + result.stdout)
        self.assertEqual(files["owned-cid.ca-exec-1.private"], b"PRIVATE-EXEC-ERROR")


if __name__ == "__main__":
    unittest.main()
