from __future__ import annotations

import copy
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import patch

import check_release_contract


ROOT = Path(__file__).resolve().parents[1]


class CapabilityLifecycleTests(unittest.TestCase):
    def load_policy(self) -> dict[str, object]:
        return json.loads(
            (ROOT / "capability-lifecycle.json").read_text(encoding="utf-8")
        )

    def check(self, document: dict[str, object], as_of: date) -> list[str]:
        with tempfile.TemporaryDirectory() as temporary_directory:
            policy = Path(temporary_directory) / "capability-lifecycle.json"
            policy.write_text(json.dumps(document), encoding="utf-8")
            with patch.object(check_release_contract, "CAPABILITY_LIFECYCLE", policy):
                return check_release_contract.check_capability_lifecycle(as_of=as_of)

    def test_checked_in_policy_is_current(self) -> None:
        self.assertEqual(self.check(self.load_policy(), date(2026, 8, 2)), [])

    def test_expired_temporary_capability_fails(self) -> None:
        errors = self.check(self.load_policy(), date(2026, 10, 2))
        self.assertTrue(any("temporary support expired" in error for error in errors))

    def test_temporary_capability_cannot_be_default(self) -> None:
        document = copy.deepcopy(self.load_policy())
        capabilities = document["capabilities"]
        assert isinstance(capabilities, list)
        ob2 = capabilities[0]
        assert isinstance(ob2, dict)
        ob2["default"] = True
        errors = self.check(document, date(2026, 8, 2))
        self.assertTrue(any("cannot be the default" in error for error in errors))

    def test_temporary_capability_requires_known_successor(self) -> None:
        document = copy.deepcopy(self.load_policy())
        capabilities = document["capabilities"]
        assert isinstance(capabilities, list)
        ob2 = capabilities[0]
        assert isinstance(ob2, dict)
        ob2["successor"] = "open-badges-4"
        errors = self.check(document, date(2026, 8, 2))
        self.assertTrue(any("unknown successor" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
