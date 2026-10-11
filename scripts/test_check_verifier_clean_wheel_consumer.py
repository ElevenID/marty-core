from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import check_verifier_clean_wheel_consumer as consumer


class CleanWheelConsumerTests(unittest.TestCase):
    def test_existing_wheel_jobs_invoke_clean_probe(self) -> None:
        root = Path(__file__).resolve().parents[1]
        invocation = 'python scripts/check_verifier_clean_wheel_consumer.py "${wheels[0]}"'
        for workflow in ("release.yml", "release-wheel-preflight.yml"):
            with self.subTest(workflow=workflow):
                contents = (root / ".github/workflows" / workflow).read_text(encoding="utf-8")
                self.assertIn(invocation, contents)
                self.assertIn('"${{ matrix.package }}" == "marty-verification"', contents)

    def test_rejects_non_verifier_wheel(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".whl") as file:
            with self.assertRaisesRegex(ValueError, "marty-verification-py wheel"):
                consumer.check_wheel(Path(file.name))

    def test_fresh_venv_installs_without_index_and_runs_both_probes(self) -> None:
        with tempfile.NamedTemporaryFile(prefix="marty_verification_py-", suffix=".whl") as file:
            wheel = Path(file.name).resolve()
            with (
                patch.object(consumer.venv.EnvBuilder, "create") as create,
                patch.object(consumer.subprocess, "run") as run,
                patch.dict(os.environ, {"PYTHONPATH": "shadow", "PYTHONHOME": "shadow"}),
            ):
                consumer.run_clean_consumer(wheel)

            create.assert_called_once()
            self.assertEqual(run.call_count, 3)
            install, import_check, fixture_probe = [call.args[0] for call in run.call_args_list]
            self.assertEqual(install[1:5], ["-m", "pip", "--isolated", "install"])
            self.assertIn("--no-index", install)
            self.assertNotIn("--no-deps", install)
            self.assertEqual(install[-1], str(wheel))
            self.assertEqual(import_check[-2:], [str(consumer.IMPORT_CHECK), "marty-verification"])
            self.assertEqual(fixture_probe[-1], str(consumer.PROBE))
            self.assertTrue(all(call.kwargs["check"] for call in run.call_args_list))
            self.assertTrue(
                all(
                    "PYTHONPATH" not in call.kwargs["env"]
                    and "PYTHONHOME" not in call.kwargs["env"]
                    for call in run.call_args_list
                )
            )


if __name__ == "__main__":
    unittest.main()
