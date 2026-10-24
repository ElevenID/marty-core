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
        invocation = (
            'python scripts/check_verifier_clean_wheel_consumer.py "${wheels[0]}"'
        )
        for workflow in ("release.yml", "release-wheel-preflight.yml"):
            with self.subTest(workflow=workflow):
                contents = (root / ".github/workflows" / workflow).read_text(
                    encoding="utf-8"
                )
                self.assertIn(invocation, contents)
                self.assertIn(
                    '"${{ matrix.package }}" == "marty-verification"', contents
                )

    def test_rejects_non_verifier_wheel(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".whl") as file:
            with self.assertRaisesRegex(ValueError, "marty-verification-py wheel"):
                consumer.check_wheel(Path(file.name))

    def test_staging_requires_both_regular_fixture_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ob2_verify_request.json").write_text("{}", encoding="utf-8")
            with patch.object(consumer, "FIXTURES", root):
                with self.assertRaisesRegex(ValueError, "ob3_verify_request.json"):
                    consumer.stage_consumer(root / "consumer")

    def test_staging_copies_only_closed_consumer_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            import_check, probe, fixtures = consumer.stage_consumer(root / "consumer")
            self.assertEqual(
                import_check.read_bytes(), consumer.IMPORT_CHECK.read_bytes()
            )
            self.assertEqual(probe.read_bytes(), consumer.PROBE.read_bytes())
            self.assertEqual(
                {path.name for path in fixtures.iterdir()}, set(consumer.FIXTURE_NAMES)
            )
            self.assertEqual(
                (fixtures / consumer.FIXTURE_NAMES[0]).read_bytes(),
                (consumer.FIXTURES / consumer.FIXTURE_NAMES[0]).read_bytes(),
            )

    def test_staging_rejects_symlink_inputs_before_copying(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(type(consumer.IMPORT_CHECK), "is_symlink", return_value=True),
                patch.object(consumer.shutil, "copyfile") as copy,
            ):
                with self.assertRaisesRegex(ValueError, "regular verifier consumer input"):
                    consumer.stage_consumer(Path(directory) / "consumer")
                copy.assert_not_called()

    def test_rejects_temporary_consumer_inside_checkout_before_execution(self) -> None:
        with tempfile.NamedTemporaryFile(
            prefix="marty_verification_py-", suffix=".whl"
        ) as file:
            checkout = Path(__file__).resolve().parents[1]
            with (
                patch.object(consumer.tempfile, "TemporaryDirectory") as temporary,
                patch.object(consumer, "stage_consumer") as stage,
                patch.object(consumer.venv, "EnvBuilder") as builder,
                patch.object(consumer.subprocess, "run") as run,
            ):
                temporary.return_value.__enter__.return_value = str(
                    checkout / "consumer-must-not-be-created"
                )
                with self.assertRaisesRegex(ValueError, "outside the source checkout"):
                    consumer.run_clean_consumer(Path(file.name))
                stage.assert_not_called()
                builder.assert_not_called()
                run.assert_not_called()

    def test_fresh_venv_installs_without_index_and_runs_both_probes(self) -> None:
        with tempfile.NamedTemporaryFile(
            prefix="marty_verification_py-", suffix=".whl"
        ) as file:
            wheel = Path(file.name).resolve()
            with (
                patch.object(consumer.venv.EnvBuilder, "create") as create,
                patch.object(consumer.subprocess, "run") as run,
                patch.dict(
                    os.environ, {"PYTHONPATH": "shadow", "PYTHONHOME": "shadow"}
                ),
            ):
                consumer.run_clean_consumer(wheel)

            create.assert_called_once()
            self.assertEqual(run.call_count, 3)
            install, import_check, fixture_probe = [
                call.args[0] for call in run.call_args_list
            ]
            self.assertEqual(install[1:5], ["-m", "pip", "--isolated", "install"])
            self.assertIn("--no-index", install)
            self.assertNotIn("--no-deps", install)
            self.assertEqual(install[-1], str(wheel))
            self.assertEqual(import_check[1], "-I")
            self.assertEqual(import_check[-1], "marty-verification")
            self.assertEqual(Path(import_check[2]).name, consumer.IMPORT_CHECK.name)
            self.assertEqual(fixture_probe[1], "-I")
            self.assertEqual(Path(fixture_probe[2]).name, consumer.PROBE.name)
            self.assertEqual(fixture_probe[-2], "--fixtures-dir")
            self.assertEqual(Path(fixture_probe[-1]).name, "fixtures")
            self.assertTrue(all(call.kwargs["check"] for call in run.call_args_list))
            self.assertEqual(
                len({call.kwargs["cwd"] for call in run.call_args_list}), 1
            )
            consumer_dir = run.call_args_list[0].kwargs["cwd"]
            self.assertEqual(consumer_dir.name, "consumer")
            self.assertFalse(
                consumer_dir.resolve().is_relative_to(
                    Path(__file__).resolve().parents[1]
                )
            )
            self.assertEqual(Path(import_check[2]).parent, consumer_dir)
            self.assertEqual(Path(fixture_probe[2]).parent, consumer_dir)
            self.assertEqual(Path(fixture_probe[-1]).parent, consumer_dir)
            self.assertTrue(
                all(
                    "PYTHONPATH" not in call.kwargs["env"]
                    and "PYTHONHOME" not in call.kwargs["env"]
                    and call.kwargs["env"]["PYTHONNOUSERSITE"] == "1"
                    for call in run.call_args_list
                )
            )


if __name__ == "__main__":
    unittest.main()
