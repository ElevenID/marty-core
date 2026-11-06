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

    def test_checked_in_retirement_has_no_future_expiry(self) -> None:
        self.assertEqual(self.check(self.load_policy(), date(2026, 11, 6)), [])
        self.assertEqual(self.check(self.load_policy(), date(2030, 1, 1)), [])

    def test_retired_capability_cannot_reactivate(self) -> None:
        for status in ("current", "temporary"):
            with self.subTest(status=status):
                document = copy.deepcopy(self.load_policy())
                document["capabilities"][0]["status"] = status
                errors = self.check(document, date(2026, 11, 6))
                self.assertTrue(any("must remain retired" in error for error in errors))

    def test_retired_capability_cannot_be_default_or_expose_interfaces(self) -> None:
        for field, value, message in (
            ("default", True, "cannot be the default"),
            ("public_interfaces", ["legacy.verify"], "cannot expose public interfaces"),
            ("removed_interfaces", [], "must record removed APIs"),
            ("retired_on", "not-a-date", "must be an ISO calendar date"),
            ("target_removal", "2026-11-09", "cannot retain temporary deadlines"),
            ("successor", "open-badges-4", "unknown successor"),
        ):
            with self.subTest(field=field):
                document = copy.deepcopy(self.load_policy())
                document["capabilities"][0][field] = value
                errors = self.check(document, date(2026, 11, 6))
                self.assertTrue(any(message in error for error in errors), errors)

    def temporary_policy(self) -> dict[str, object]:
        document = self.load_policy()
        document["capabilities"].append({
            "id": "test-temporary-capability",
            "status": "temporary",
            "default": False,
            "successor": "open-badges-3",
            "tracking_issue": "https://github.com/ElevenID/marty-core/issues/96",
            "public_interfaces": ["test.temporary"],
            "review_on": "2026-11-06",
            "target_removal": "2026-11-09",
        })
        return document

    def test_other_temporary_capabilities_still_expire(self) -> None:
        document = self.temporary_policy()
        self.assertEqual(self.check(document, date(2026, 11, 9)), [])
        errors = self.check(document, date(2026, 11, 10))
        self.assertTrue(any("temporary support expired" in error for error in errors))

    def test_temporary_capability_cannot_be_default(self) -> None:
        document = self.temporary_policy()
        document["capabilities"][-1]["default"] = True
        errors = self.check(document, date(2026, 11, 6))
        self.assertTrue(any("cannot be the default" in error for error in errors))

    def test_temporary_capability_requires_known_successor(self) -> None:
        document = self.temporary_policy()
        document["capabilities"][-1]["successor"] = "open-badges-4"
        errors = self.check(document, date(2026, 11, 6))
        self.assertTrue(any("unknown successor" in error for error in errors))


class ReleaseChecksumPolicyTests(unittest.TestCase):
    def test_checked_in_release_workflow_excludes_and_verifies_manifest(self) -> None:
        self.assertEqual(check_release_contract.check_release_checksum_policy(), [])

    def test_checksum_manifest_cannot_include_itself(self) -> None:
        errors = check_release_contract.check_release_checksum_policy(
            "find . -type f ! -name SHA256SUMS -print0 | "
            "xargs -0 sha256sum > SHA256SUMS\n"
            "find . -type f -print0 | xargs -0 sha256sum > SHA256SUMS\n"
            "sha256sum --check --strict SHA256SUMS\n"
        )
        self.assertTrue(any("includes the manifest" in error for error in errors))

    def test_release_assets_must_be_flattened_before_checksumming(self) -> None:
        errors = check_release_contract.check_release_checksum_policy(
            "find . -type f ! -name SHA256SUMS -print0 | "
            "xargs -0 sha256sum > SHA256SUMS\n"
            "sha256sum --check --strict SHA256SUMS\n"
        )
        self.assertTrue(any("must be flattened" in error for error in errors))

    def test_checksum_manifest_must_be_verified_before_publication(self) -> None:
        errors = check_release_contract.check_release_checksum_policy(
            "find . -type f ! -name SHA256SUMS -print0 | "
            "xargs -0 sha256sum > SHA256SUMS\n"
        )
        self.assertTrue(any("must verify" in error for error in errors))


class StableTagGateContractTests(unittest.TestCase):
    def test_checked_in_stable_tag_gate_is_complete(self) -> None:
        self.assertEqual(check_release_contract.check_stable_tag_gate(), [])

    def test_release_policy_rejects_a_removed_push_trigger(self) -> None:
        policy = json.loads(
            (ROOT / ".github" / "stable-tag-policy.json").read_text(encoding="utf-8")
        )
        policy["required_workflows"][0]["event"] = "push"
        errors = check_release_contract.check_stable_tag_policy(policy)
        self.assertTrue(any("must use workflow_dispatch" in error for error in errors))


class NativeBuildCacheContractTests(unittest.TestCase):
    def test_checked_in_ci_uses_an_approved_native_build_cache(self) -> None:
        self.assertEqual(check_release_contract.check_native_build_cache_scope(), [])

    def test_accepts_platform_and_toolchain_scoped_target_cache(self) -> None:
        workflow = (
            "key: ${{ runner.os }}-${{ runner.arch }}-"
            "${{ env.RUSTUP_TOOLCHAIN }}-cargo-build-target\n"
        )
        self.assertEqual(
            check_release_contract.check_native_build_cache_scope(workflow), []
        )

    def test_rejects_unpinned_or_incomplete_sccache(self) -> None:
        workflow = "RUSTC_WRAPPER: sccache\nSCCACHE_GHA_ENABLED: true\n"
        errors = check_release_contract.check_native_build_cache_scope(workflow)
        self.assertTrue(any("missing a pinned sccache" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
