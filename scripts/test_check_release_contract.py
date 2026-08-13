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
