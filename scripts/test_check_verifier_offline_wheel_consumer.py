from __future__ import annotations

import json
import importlib.machinery
import tempfile
import unittest
from pathlib import Path

import check_verifier_offline_wheel_consumer as probe


class OfflineWheelConsumerTests(unittest.TestCase):
    def test_wrong_key_rust_fixture_changes_trigger_wheel_preflight(self) -> None:
        workflow = (
            probe.FIXTURES.parents[3] / ".github/workflows/release-wheel-preflight.yml"
        )
        self.assertIn(
            '      - "marty-verification/tests/open_badges_interop.rs"',
            workflow.read_text(encoding="utf-8"),
        )

    @staticmethod
    def _recording_verifier(seen: list[dict]) -> object:
        def fake_verify(raw: str) -> str:
            seen.append(json.loads(raw))
            return json.dumps({"valid": len(seen) == 1})

        return fake_verify

    def test_rejects_socket_operations(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "network operation"):
            probe.deny_network("socket.connect", ())
        probe.deny_network("open", ())

    def test_requires_native_extension_inside_consumer_venv(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public = root / "Lib/site-packages/marty_verification_py/__init__.py"
            native = public.with_name(
                "_marty_verification" + importlib.machinery.EXTENSION_SUFFIXES[0]
            )
            probe.require_installed_native(public, native, root)
            with self.assertRaisesRegex(RuntimeError, "outside the consumer venv"):
                probe.require_installed_native(
                    Path(directory).parent / "shadow.py", native, root
                )
            with self.assertRaisesRegex(RuntimeError, "outside the consumer venv"):
                probe.require_installed_native(
                    public, Path(directory).parent / native.name, root
                )
            with self.assertRaisesRegex(RuntimeError, "native extension is missing"):
                probe.require_installed_native(public, native.with_suffix(".py"), root)

    def test_missing_staged_fixture_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                probe.verify_fixture(
                    lambda _: '{"valid": true}',
                    "ob3_verify_request.json",
                    Path(directory),
                )

    def test_fixture_probe_requires_valid_then_invalid(self) -> None:
        for fixture in ("ob3_verify_request.json",):
            with self.subTest(fixture=fixture):
                seen = []

                probe.verify_fixture(self._recording_verifier(seen), fixture)
                self.assertEqual(len(seen), 3)
                self.assertNotEqual(seen[0], seen[1])
                key_id = seen[0]["credential"]["proof"]["verificationMethod"]
                self.assertNotEqual(
                    seen[0]["document_store"][key_id]["publicKeyJwk"]["x"],
                    probe.OTHER_ED25519_PUBLIC_KEY,
                )
                self.assertEqual(
                    seen[2]["document_store"][key_id]["publicKeyJwk"]["x"],
                    probe.OTHER_ED25519_PUBLIC_KEY,
                )
                self.assertEqual(
                    seen[0]["credential"],
                    seen[2]["credential"],
                )
                self.assertEqual(
                    seen[1]["credential"]["credentialSubject"]["achievement"]["name"],
                    "Tampered",
                )

    def test_rejects_false_positive_and_false_negative(self) -> None:
        fixture = "ob3_verify_request.json"
        with self.assertRaisesRegex(RuntimeError, "valid signed fixture was rejected"):
            probe.verify_fixture(lambda _: '{"valid": false}', fixture)
        with self.assertRaisesRegex(RuntimeError, "negative fixture was accepted"):
            probe.verify_fixture(lambda _: '{"valid": true}', fixture)

        calls = 0

        def accepts_wrong_key(_: str) -> str:
            nonlocal calls
            calls += 1
            return json.dumps({"valid": calls != 2})

        with self.assertRaisesRegex(RuntimeError, "mismatched issuer key was accepted"):
            probe.verify_fixture(accepts_wrong_key, fixture)


    def test_retired_fixture_requires_explicit_retirement_error(self) -> None:
        seen = []

        def reject(raw: str) -> str:
            seen.append(json.loads(raw))
            raise ValueError("Open Badges 2 is retired; obtain a newly issued Open Badges 3 credential")

        probe.reject_retired_fixture(reject)
        self.assertEqual(seen[0]["credential"]["type"], "Assertion")
        self.assertIn("signature", seen[0]["credential"])
        for result in ('{"valid": true}', '{"valid": false}'):
            with self.assertRaisesRegex(RuntimeError, "reached an active verifier"):
                probe.reject_retired_fixture(lambda _: result)

        def wrong_error(_: str) -> str:
            raise ValueError("Invalid OB3 credential")

        with self.assertRaisesRegex(RuntimeError, "unexpected error"):
            probe.reject_retired_fixture(wrong_error)

    def test_ob3_caller_time_uses_signed_fixture_and_rejects_naive_time(self) -> None:
        seen: list[tuple[dict, str]] = []

        def fake_verify(raw: str, when: str) -> str:
            seen.append((json.loads(raw), when))
            if when == probe.OB3_EVALUATION_TIME:
                return '{"valid": true}'
            raise ValueError("evaluation_time must be RFC 3339 with an explicit offset")

        probe.verify_ob3_at_caller_time(fake_verify)
        self.assertEqual(len(seen), 2)
        self.assertEqual(seen[0][0], seen[1][0])
        self.assertEqual(seen[0][1], "2026-11-12T00:00:00Z")
        self.assertEqual(seen[1][1], "2026-01-01T00:00:00")
        self.assertIn("proof", seen[0][0]["credential"])

    def test_ob3_caller_time_fails_closed(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "caller-time fixture was rejected"):
            probe.verify_ob3_at_caller_time(lambda _raw, _when: '{"valid": false}')
        with self.assertRaisesRegex(RuntimeError, "timezone-free timestamp"):
            probe.verify_ob3_at_caller_time(lambda _raw, _when: '{"valid": true}')

        def unexpected_error(_raw: str, when: str) -> str:
            if when == probe.OB3_EVALUATION_TIME:
                return '{"valid": true}'
            raise ValueError("unrelated failure")

        with self.assertRaisesRegex(RuntimeError, "unexpected error"):
            probe.verify_ob3_at_caller_time(unexpected_error)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                probe.verify_ob3_at_caller_time(
                    lambda _raw, _when: '{"valid": true}', Path(directory)
                )


if __name__ == "__main__":
    unittest.main()
