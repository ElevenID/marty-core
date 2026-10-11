from __future__ import annotations

import json
import unittest

import check_verifier_offline_wheel_consumer as probe


class OfflineWheelConsumerTests(unittest.TestCase):
    def test_rejects_socket_operations(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "network operation"):
            probe.deny_network("socket.connect", ())
        probe.deny_network("open", ())

    def test_fixture_probe_requires_valid_then_invalid(self) -> None:
        for fixture in ("ob2_verify_request.json", "ob3_verify_request.json"):
            with self.subTest(fixture=fixture):
                seen = []

                def fake_verify(raw: str) -> str:
                    seen.append(json.loads(raw))
                    return json.dumps({"valid": len(seen) == 1})

                probe.verify_fixture(fake_verify, fixture)
                self.assertEqual(len(seen), 2)
                self.assertNotEqual(seen[0], seen[1])

    def test_rejects_false_positive_and_false_negative(self) -> None:
        fixture = "ob2_verify_request.json"
        with self.assertRaisesRegex(RuntimeError, "valid signed fixture was rejected"):
            probe.verify_fixture(lambda _: '{"valid": false}', fixture)
        with self.assertRaisesRegex(RuntimeError, "negative fixture was accepted"):
            probe.verify_fixture(lambda _: '{"valid": true}', fixture)


if __name__ == "__main__":
    unittest.main()
