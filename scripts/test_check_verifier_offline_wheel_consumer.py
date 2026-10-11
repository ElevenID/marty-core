from __future__ import annotations

import json
import unittest

import check_verifier_offline_wheel_consumer as probe


class OfflineWheelConsumerTests(unittest.TestCase):
    def test_wrong_key_rust_fixture_changes_trigger_wheel_preflight(self) -> None:
        workflow = probe.FIXTURES.parents[3] / ".github/workflows/release-wheel-preflight.yml"
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

    def test_fixture_probe_requires_valid_then_invalid(self) -> None:
        for fixture in ("ob2_verify_request.json", "ob3_verify_request.json"):
            with self.subTest(fixture=fixture):
                seen = []

                probe.verify_fixture(self._recording_verifier(seen), fixture)
                self.assertEqual(len(seen), 3)
                self.assertNotEqual(seen[0], seen[1])
                self.assertEqual(seen[0]["document_store"][probe.ISSUER_KEY_ID]["publicKeyJwk"]["x"],
                                 "ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ")
                self.assertEqual(seen[2]["document_store"][probe.ISSUER_KEY_ID]["publicKeyJwk"]["x"],
                                 probe.OTHER_ED25519_PUBLIC_KEY)
                self.assertEqual(seen[0]["assertion" if fixture.startswith("ob2") else "credential"],
                                 seen[2]["assertion" if fixture.startswith("ob2") else "credential"])
                if fixture.startswith("ob2"):
                    self.assertEqual(seen[1]["assertion"]["id"], "urn:uuid:tampered")
                else:
                    self.assertEqual(
                        seen[1]["credential"]["credentialSubject"]["achievement"]["name"],
                        "Tampered",
                    )

    def test_rejects_false_positive_and_false_negative(self) -> None:
        fixture = "ob2_verify_request.json"
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


if __name__ == "__main__":
    unittest.main()
