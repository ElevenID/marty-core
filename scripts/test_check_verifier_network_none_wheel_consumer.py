from __future__ import annotations

import errno
import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import check_verifier_network_none_inner as inner
import check_verifier_network_none_wheel_consumer as consumer

IMAGE = "python:3.11-slim@sha256:" + "a" * 64


class NetworkNoneWheelConsumerTests(unittest.TestCase):
    def test_rejects_unpinned_image_and_non_linux_wheel(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheelhouse = root / "wheelhouse"
            wheelhouse.mkdir()
            wheel = root / "marty_verification_py-0.1-cp311-cp311-win_amd64.whl"
            wheel.touch()
            with self.assertRaisesRegex(ValueError, "Linux/x86_64"):
                consumer.check_inputs(wheel, wheelhouse, IMAGE)
            wheel = (
                root / "marty_verification_py-0.1-cp311-cp311-macosx_11_0_x86_64.whl"
            )
            wheel.touch()
            with self.assertRaisesRegex(ValueError, "Linux/x86_64"):
                consumer.check_inputs(wheel, wheelhouse, IMAGE)
            wheel = (
                root / "marty_verification_py-0.1-cp311-cp311-manylinux_2_17_x86_64.whl"
            )
            wheel.touch()
            with self.assertRaisesRegex(ValueError, "digest-pinned"):
                consumer.check_inputs(wheel, wheelhouse, "python:3.11-slim")

    def test_rejects_non_wheel_or_duplicate_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheelhouse = root / "wheelhouse"
            wheelhouse.mkdir()
            wheel = (
                root / "marty_verification_py-0.1-cp311-cp311-manylinux_2_17_x86_64.whl"
            )
            wheel.touch()
            (wheelhouse / "notes.txt").touch()
            with self.assertRaisesRegex(ValueError, "only regular wheel"):
                consumer.check_inputs(wheel, wheelhouse, IMAGE)
            (wheelhouse / "notes.txt").unlink()
            (wheelhouse / wheel.name).touch()
            with self.assertRaisesRegex(ValueError, "duplicates"):
                consumer.check_inputs(wheel, wheelhouse, IMAGE)

    def test_inspect_requires_preloaded_linux_amd64_image(self) -> None:
        with patch.object(consumer.subprocess, "run") as run:
            run.return_value.stdout = json.dumps(
                [{"Os": "linux", "Architecture": "arm64"}]
            )
            with self.assertRaisesRegex(RuntimeError, "Linux/amd64"):
                consumer.check_preloaded_image(IMAGE)
            run.assert_called_once_with(
                ["docker", "image", "inspect", IMAGE],
                check=True,
                text=True,
                capture_output=True,
                timeout=consumer.INSPECT_TIMEOUT,
            )

    def test_stages_only_inputs_and_invokes_network_none_container(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheelhouse = root / "wheelhouse"
            wheelhouse.mkdir()
            wheel = (
                root / "marty_verification_py-0.1-cp311-cp311-manylinux_2_17_x86_64.whl"
            )
            wheel.write_bytes(b"exact wheel")
            (wheelhouse / "dependency-1-py3-none-any.whl").write_bytes(b"dependency")
            output = io.StringIO()
            with (
                patch.object(consumer, "check_preloaded_image") as inspect,
                patch.object(consumer.subprocess, "run") as run,
                redirect_stdout(output),
            ):

                def inspect_staged(command: list[str], **_kwargs: object) -> None:
                    mount = command[command.index("--mount") + 1]
                    staged = Path(
                        mount.removeprefix("type=bind,src=").removesuffix(
                            ",dst=/input,readonly"
                        )
                    )
                    self.assertEqual(
                        {path.name for path in staged.iterdir()},
                        {
                            "fixtures",
                            "wheels",
                            consumer.INNER.name,
                            "check_python_wheel_import.py",
                            "check_verifier_offline_wheel_consumer.py",
                        },
                    )
                    self.assertEqual(
                        {path.name for path in (staged / "wheels").iterdir()},
                        {wheel.name, "dependency-1-py3-none-any.whl"},
                    )
                    self.assertFalse(
                        staged.is_relative_to(Path(__file__).resolve().parents[1])
                    )

                run.side_effect = inspect_staged
                consumer.run_network_none_consumer(wheel, wheelhouse, IMAGE)
            inspect.assert_called_once_with(IMAGE)
            command = run.call_args.args[0]
            self.assertEqual(command[:3], ["docker", "run", "--rm"])
            for option, value in (
                ("--pull", "never"),
                ("--platform", "linux/amd64"),
                ("--network", "none"),
                ("--workdir", "/input"),
                ("--memory", "1g"),
                ("--memory-swap", "1g"),
                ("--cpus", "2"),
                ("--pids-limit", "128"),
                ("--cap-drop", "ALL"),
                ("--security-opt", "no-new-privileges"),
                ("--tmpfs", "/tmp:rw,nosuid,nodev,size=1073741824,mode=1777"),
            ):
                self.assertEqual(command[command.index(option) + 1], value)
            self.assertIn("--read-only", command)
            self.assertEqual(
                command[-4:],
                [IMAGE, "python", "-I", "/input/check_verifier_network_none_inner.py"],
            )
            self.assertTrue(run.call_args.kwargs["check"])
            receipt = json.loads(output.getvalue())
            self.assertFalse(receipt["release_qualified"])
            self.assertEqual(receipt["image"], IMAGE)
            inputs = {row["path"]: row for row in receipt["inputs"]}
            self.assertEqual(
                inputs["wheels/" + wheel.name]["sha256"],
                "4010629315422be8f730c91089f2352c649fa6d121fe05206bd6a16a9a5979b9",
            )
            self.assertEqual(run.call_args.kwargs["timeout"], consumer.CONSUMER_TIMEOUT)
            name = command[command.index("--name") + 1]
            label = command[command.index("--label") + 1]
            self.assertEqual(
                label,
                consumer.RUN_LABEL
                + "="
                + name.removeprefix("marty-verifier-network-none-"),
            )

    def test_timeout_cleans_only_the_invocation_container(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheelhouse = root / "wheelhouse"
            wheelhouse.mkdir()
            wheel = root / "marty_verification_py-0.1-cp311-cp311-linux_x86_64.whl"
            wheel.write_bytes(b"exact wheel")
            with (
                patch.object(consumer, "check_preloaded_image"),
                patch.object(
                    consumer.subprocess,
                    "run",
                    side_effect=subprocess.TimeoutExpired(
                        "docker", consumer.CONSUMER_TIMEOUT
                    ),
                ) as run,
                patch.object(consumer, "cleanup_owned_container") as cleanup,
            ):
                with self.assertRaises(subprocess.TimeoutExpired):
                    consumer.run_network_none_consumer(wheel, wheelhouse, IMAGE)
            command = run.call_args.args[0]
            name = command[command.index("--name") + 1]
            cleanup.assert_called_once_with(
                name, name.removeprefix("marty-verifier-network-none-")
            )

    def test_cleanup_checks_label_and_uses_immutable_container_id(self) -> None:
        run_id = "a" * 32
        name = "marty-verifier-network-none-" + run_id
        container_id = "b" * 64
        for label, valid in (("wrong", False), (run_id, True)):
            with (
                self.subTest(label=label),
                patch.object(consumer.subprocess, "run") as run,
            ):
                run.return_value = subprocess.CompletedProcess(
                    [],
                    0,
                    json.dumps(
                        [
                            {
                                "Id": container_id,
                                "Name": "/" + name,
                                "Config": {"Labels": {consumer.RUN_LABEL: label}},
                            }
                        ]
                    ),
                    "",
                )
                if not valid:
                    with self.assertRaisesRegex(RuntimeError, "not owned"):
                        consumer.cleanup_owned_container(name, run_id)
                    self.assertEqual(run.call_count, 1)
                else:
                    consumer.cleanup_owned_container(name, run_id)
                    self.assertEqual(
                        run.call_args.args[0],
                        ["docker", "container", "rm", "--force", container_id],
                    )
                    self.assertEqual(
                        run.call_args.kwargs["timeout"], consumer.INSPECT_TIMEOUT
                    )

    def test_cleanup_rejects_unknown_inspection_failure(self) -> None:
        run_id = "a" * 32
        with patch.object(consumer.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess(
                [], 1, "", "daemon unavailable"
            )
            with self.assertRaisesRegex(RuntimeError, "could not verify"):
                consumer.cleanup_owned_container(
                    "marty-verifier-network-none-" + run_id, run_id
                )
            self.assertEqual(run.call_count, 1)

    def test_cleanup_rejects_changed_name_or_invalid_container_id(self) -> None:
        run_id = "a" * 32
        name = "marty-verifier-network-none-" + run_id
        for observed_name, container_id in (
            ("/another", "b" * 64),
            ("/" + name, "short"),
        ):
            with (
                self.subTest(name=observed_name, cid=container_id),
                patch.object(consumer.subprocess, "run") as run,
            ):
                run.return_value = subprocess.CompletedProcess(
                    [],
                    0,
                    json.dumps(
                        [
                            {
                                "Id": container_id,
                                "Name": observed_name,
                                "Config": {"Labels": {consumer.RUN_LABEL: run_id}},
                            }
                        ]
                    ),
                    "",
                )
                with self.assertRaisesRegex(RuntimeError, "not owned"):
                    consumer.cleanup_owned_container(name, run_id)
                self.assertEqual(run.call_count, 1)

    def test_already_removed_container_needs_no_cleanup(self) -> None:
        run_id = "a" * 32
        with patch.object(consumer.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess(
                [], 1, "", "Error: No such container"
            )
            consumer.cleanup_owned_container(
                "marty-verifier-network-none-" + run_id, run_id
            )
            self.assertEqual(run.call_count, 1)

    def test_fingerprints_bind_actual_staged_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "input.whl").write_bytes(b"a")
            first = consumer.staged_fingerprints(root)
            (root / "input.whl").write_bytes(b"b")
            second = consumer.staged_fingerprints(root)
            self.assertEqual(first[0]["path"], "input.whl")
            self.assertEqual(first[0]["bytes"], 1)
            self.assertNotEqual(first[0]["sha256"], second[0]["sha256"])

    def test_inner_rejects_extra_interface_and_unexpected_connection(self) -> None:
        with (
            patch.object(inner.sys, "platform", "linux"),
            patch.object(inner.platform, "machine", return_value="x86_64"),
            patch.object(
                inner.socket, "if_nameindex", return_value=[(1, "lo"), (2, "eth0")]
            ),
            self.assertRaisesRegex(RuntimeError, "loopback-only"),
        ):
            inner.require_network_none()
        with (
            patch.object(inner.sys, "platform", "linux"),
            patch.object(inner.platform, "machine", return_value="x86_64"),
            patch.object(inner.socket, "if_nameindex", return_value=[(1, "lo")]),
            patch.object(inner.socket, "socket") as socket,
        ):
            socket.return_value.__enter__.return_value.connect.return_value = None
            with self.assertRaisesRegex(RuntimeError, "unexpectedly connected"):
                inner.require_network_none()

    def test_inner_requires_no_route_errno_not_refusal_or_timeout(self) -> None:
        with (
            patch.object(inner.sys, "platform", "linux"),
            patch.object(inner.platform, "machine", return_value="x86_64"),
            patch.object(inner.socket, "if_nameindex", return_value=[(1, "lo")]),
            patch.object(inner.socket, "socket") as socket,
        ):
            connect = socket.return_value.__enter__.return_value.connect
            connect.side_effect = OSError(errno.ENETUNREACH, "Network unreachable")
            inner.require_network_none()
            for error in (
                ConnectionRefusedError(errno.ECONNREFUSED, "Refused"),
                TimeoutError(),
            ):
                with self.subTest(error=type(error).__name__):
                    connect.side_effect = error
                    with self.assertRaisesRegex(
                        RuntimeError, "expected no network route"
                    ):
                        inner.require_network_none()

    def test_inner_installs_exact_wheel_offline_and_runs_existing_probes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            staged = Path(directory)
            wheels = staged / "wheels"
            wheels.mkdir()
            wheel = (
                wheels
                / "marty_verification_py-0.1-cp311-cp311-manylinux_2_17_x86_64.whl"
            )
            wheel.touch()
            with (
                patch.object(
                    inner,
                    "__file__",
                    str(staged / "check_verifier_network_none_inner.py"),
                ),
                patch.object(inner, "require_network_none") as network,
                patch.object(inner.venv.EnvBuilder, "create") as create,
                patch.object(inner.subprocess, "run") as run,
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(inner.main(), 0)
            network.assert_called_once()
            create.assert_called_once()
            self.assertEqual(run.call_count, 3)
            install, import_check, fixture_probe = [
                call.args[0] for call in run.call_args_list
            ]
            self.assertIn("--no-index", install)
            self.assertEqual(install[-1], str(wheel))
            self.assertEqual(install[install.index("--find-links") + 1], str(wheels))
            self.assertEqual(import_check[-1], "marty-verification")
            self.assertEqual(
                Path(fixture_probe[2]).name,
                "check_verifier_offline_wheel_consumer.py",
            )
            self.assertEqual(fixture_probe[-1], str(staged / "fixtures"))
            self.assertTrue(all(call.kwargs["check"] for call in run.call_args_list))
            self.assertTrue(
                all(
                    call.kwargs["timeout"] == inner.PROBE_TIMEOUT
                    for call in run.call_args_list
                )
            )


if __name__ == "__main__":
    unittest.main()
