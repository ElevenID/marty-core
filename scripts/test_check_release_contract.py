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
    @staticmethod
    def wasm_security_workflow(crypto_steps: str) -> str:
        pinned = (
            "mozilla-actions/sccache-action@"
            "fc920bf0ec8de6ee65d409111f7ec508035751ba"
        )
        return f"""jobs:
  oid4vci-wasm-security:
    steps:
      - uses: {pinned}
      - run: >-
          cargo test --locked -p marty-oid4vci
          --target wasm32-unknown-unknown
          --no-default-features --features verifier
          --test wasm_crypto_provider
          -- --nocapture
  crypto-wasm-security:
    steps:
      - uses: {pinned}
{crypto_steps}"""

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

    def test_checked_in_wasm_security_jobs_provide_sccache(self) -> None:
        self.assertEqual(check_release_contract.check_wasm_security_cache_setup(), [])

    def test_rejects_wasm_security_job_with_missing_rust_wrapper(self) -> None:
        pinned = (
            "mozilla-actions/sccache-action@"
            "fc920bf0ec8de6ee65d409111f7ec508035751ba"
        )
        workflow = f"""jobs:
  oid4vci-wasm-security:
    steps:
      - uses: {pinned}
  crypto-wasm-security:
    steps:
      - run: cargo test --target wasm32-unknown-unknown
"""
        errors = check_release_contract.check_wasm_security_cache_setup(workflow)
        self.assertTrue(any("crypto-wasm-security inherits" in error for error in errors))

    def test_rejects_wasm_security_cache_installed_after_cargo(self) -> None:
        pinned = (
            "mozilla-actions/sccache-action@"
            "fc920bf0ec8de6ee65d409111f7ec508035751ba"
        )
        workflow = f"""jobs:
  oid4vci-wasm-security:
    steps:
      - uses: {pinned}
      - run: cargo test --target wasm32-unknown-unknown
  crypto-wasm-security:
    steps:
      - run: cargo test --target wasm32-unknown-unknown
      - uses: {pinned}
"""
        errors = check_release_contract.check_wasm_security_cache_setup(workflow)
        self.assertTrue(any("before its first cargo command" in error for error in errors))

    def test_rejects_commented_wasm_security_cache_action(self) -> None:
        pinned = (
            "mozilla-actions/sccache-action@"
            "fc920bf0ec8de6ee65d409111f7ec508035751ba"
        )
        workflow = f"""jobs:
  oid4vci-wasm-security:
    steps:
      - uses: {pinned}
  crypto-wasm-security:
    steps:
      # uses: {pinned}
      - run: cargo test --target wasm32-unknown-unknown
"""
        errors = check_release_contract.check_wasm_security_cache_setup(workflow)
        self.assertTrue(any("without installing pinned sccache" in error for error in errors))

    def test_rejects_wasm_security_cache_text_inside_run_block(self) -> None:
        pinned = (
            "mozilla-actions/sccache-action@"
            "fc920bf0ec8de6ee65d409111f7ec508035751ba"
        )
        workflow = f"""jobs:
  oid4vci-wasm-security:
    steps:
      - uses: {pinned}
      - run: cargo test --target wasm32-unknown-unknown
  crypto-wasm-security:
    steps:
      - run: |
          uses: {pinned}
          cargo test --target wasm32-unknown-unknown
"""
        errors = check_release_contract.check_wasm_security_cache_setup(workflow)
        self.assertTrue(any("without installing pinned sccache" in error for error in errors))

    def test_rejects_conditional_wasm_security_cache_action(self) -> None:
        pinned = (
            "mozilla-actions/sccache-action@"
            "fc920bf0ec8de6ee65d409111f7ec508035751ba"
        )
        workflow = f"""jobs:
  oid4vci-wasm-security:
    steps:
      - uses: {pinned}
  crypto-wasm-security:
    steps:
      - uses: {pinned}
        if: false
      - run: cargo test --target wasm32-unknown-unknown
"""
        errors = check_release_contract.check_wasm_security_cache_setup(workflow)
        self.assertTrue(any("without installing pinned sccache" in error for error in errors))

    def test_rejects_equivalent_conditional_cache_key_spellings(self) -> None:
        pinned = (
            "mozilla-actions/sccache-action@"
            "fc920bf0ec8de6ee65d409111f7ec508035751ba"
        )
        for condition in ("if : false", '"if": false', "'if' : false"):
            with self.subTest(condition=condition):
                workflow = f"""jobs:
  oid4vci-wasm-security:
    steps:
      - uses: {pinned}
  crypto-wasm-security:
    steps:
      - uses: {pinned}
        {condition}
      - run: cargo test --target wasm32-unknown-unknown
"""
                errors = check_release_contract.check_wasm_security_cache_setup(
                    workflow
                )
                self.assertTrue(
                    any("without installing pinned sccache" in error for error in errors)
                )

    def test_rejects_equivalent_run_key_before_cache_action(self) -> None:
        pinned = (
            "mozilla-actions/sccache-action@"
            "fc920bf0ec8de6ee65d409111f7ec508035751ba"
        )
        workflow = f"""jobs:
  oid4vci-wasm-security:
    steps:
      - uses: {pinned}
  crypto-wasm-security:
    steps:
      - "run" : cargo test --target wasm32-unknown-unknown
      - uses : {pinned}
"""
        errors = check_release_contract.check_wasm_security_cache_setup(workflow)
        self.assertTrue(any("before its first cargo command" in error for error in errors))

    def test_rejects_conditional_wasm_security_job(self) -> None:
        pinned = (
            "mozilla-actions/sccache-action@"
            "fc920bf0ec8de6ee65d409111f7ec508035751ba"
        )
        workflow = f"""jobs:
  oid4vci-wasm-security:
    steps:
      - uses: {pinned}
      - run: cargo test --target wasm32-unknown-unknown
  crypto-wasm-security:
    if: false
    steps:
      - uses: {pinned}
      - run: cargo test --target wasm32-unknown-unknown
"""
        errors = check_release_contract.check_wasm_security_cache_setup(workflow)
        self.assertTrue(any("must run unconditionally" in error for error in errors))

    def test_rejects_conditional_wasm_security_cargo_test(self) -> None:
        pinned = (
            "mozilla-actions/sccache-action@"
            "fc920bf0ec8de6ee65d409111f7ec508035751ba"
        )
        workflow = f"""jobs:
  oid4vci-wasm-security:
    steps:
      - uses: {pinned}
      - run: cargo test --target wasm32-unknown-unknown
  crypto-wasm-security:
    steps:
      - uses: {pinned}
      - run: cargo test --target wasm32-unknown-unknown
      - run: cargo test another_selected_case
        if: false
"""
        errors = check_release_contract.check_wasm_security_cache_setup(workflow)
        self.assertTrue(
            any("every cargo test step unconditionally" in error for error in errors)
        )

    def test_rejects_wasm_security_job_without_cargo_test(self) -> None:
        pinned = (
            "mozilla-actions/sccache-action@"
            "fc920bf0ec8de6ee65d409111f7ec508035751ba"
        )
        workflow = f"""jobs:
  oid4vci-wasm-security:
    steps:
      - uses: {pinned}
      - run: cargo test --target wasm32-unknown-unknown
  crypto-wasm-security:
    steps:
      - uses: {pinned}
      - run: cargo check --target wasm32-unknown-unknown
"""
        errors = check_release_contract.check_wasm_security_cache_setup(workflow)
        self.assertTrue(any("must execute a cargo test" in error for error in errors))

    def test_rejects_cargo_test_text_without_direct_execution(self) -> None:
        pinned = (
            "mozilla-actions/sccache-action@"
            "fc920bf0ec8de6ee65d409111f7ec508035751ba"
        )
        workflow = f"""jobs:
  oid4vci-wasm-security:
    steps:
      - uses: {pinned}
      - run: cargo test --target wasm32-unknown-unknown
  crypto-wasm-security:
    steps:
      - uses: {pinned}
      - run: echo cargo test --target wasm32-unknown-unknown
"""
        errors = check_release_contract.check_wasm_security_cache_setup(workflow)
        self.assertTrue(any("must execute a cargo test" in error for error in errors))

    def test_rejects_nonexecuting_cargo_test_flags(self) -> None:
        pinned = (
            "mozilla-actions/sccache-action@"
            "fc920bf0ec8de6ee65d409111f7ec508035751ba"
        )
        for arguments in ("--no-run", "--help", "-- --list"):
            with self.subTest(arguments=arguments):
                workflow = f"""jobs:
  oid4vci-wasm-security:
    steps:
      - uses: {pinned}
      - run: cargo test --target wasm32-unknown-unknown
  crypto-wasm-security:
    steps:
      - uses: {pinned}
      - run: cargo test {arguments}
"""
                errors = check_release_contract.check_wasm_security_cache_setup(
                    workflow
                )
                self.assertTrue(any("must execute tests" in error for error in errors))

    def test_rejects_shell_suppressed_cargo_test_failures(self) -> None:
        pinned = (
            "mozilla-actions/sccache-action@"
            "fc920bf0ec8de6ee65d409111f7ec508035751ba"
        )
        for suffix in ("|| true", "; exit 0", "&"):
            with self.subTest(suffix=suffix):
                workflow = f"""jobs:
  oid4vci-wasm-security:
    steps:
      - uses: {pinned}
      - run: cargo test --target wasm32-unknown-unknown
  crypto-wasm-security:
    steps:
      - uses: {pinned}
      - run: cargo test --target wasm32-unknown-unknown {suffix}
"""
                errors = check_release_contract.check_wasm_security_cache_setup(
                    workflow
                )
                self.assertTrue(
                    any("directly enforce their exit status" in error for error in errors)
                )

    def test_rejects_multiline_failure_masking(self) -> None:
        workflow = self.wasm_security_workflow(
            """      - run: |
          set +e
          cargo test --locked -p marty-crypto --target wasm32-unknown-unknown --no-default-features --features kdf,symmetric --test wasm_key_derivation -- --nocapture
          true
"""
        )
        errors = check_release_contract.check_wasm_security_cache_setup(workflow)
        self.assertTrue(any("exact approved Cargo test script" in error for error in errors))

    def test_rejects_shell_conditional_cargo_test(self) -> None:
        workflow = self.wasm_security_workflow(
            """      - run: |
          if false; then
            cargo test --locked -p marty-crypto --target wasm32-unknown-unknown --no-default-features --features kdf,symmetric --test wasm_key_derivation -- --nocapture
          fi
"""
        )
        errors = check_release_contract.check_wasm_security_cache_setup(workflow)
        self.assertTrue(any("exact approved Cargo test script" in error for error in errors))

    def test_rejects_continued_nonexecuting_cargo_test_flag(self) -> None:
        workflow = self.wasm_security_workflow(
            """      - run: |
          cargo test --locked -p marty-crypto --target wasm32-unknown-unknown \\
            --no-run
"""
        )
        errors = check_release_contract.check_wasm_security_cache_setup(workflow)
        self.assertTrue(any("exact approved Cargo test script" in error for error in errors))

    def test_rejects_unapproved_cargo_test_filter(self) -> None:
        workflow = self.wasm_security_workflow(
            """      - run: cargo test definitely_no_such_test
"""
        )
        errors = check_release_contract.check_wasm_security_cache_setup(workflow)
        self.assertTrue(any("exact approved Cargo test script" in error for error in errors))

    def test_rejects_cargo_test_pipeline(self) -> None:
        workflow = self.wasm_security_workflow(
            """      - run: cargo test --locked -p marty-crypto | true
"""
        )
        errors = check_release_contract.check_wasm_security_cache_setup(workflow)
        self.assertTrue(any("exact approved Cargo test script" in error for error in errors))

    def test_rejects_folded_comment_that_suppresses_wasm_test(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        original = "        run: >-\n          cargo test --locked -p marty-oid4vci"
        replacement = (
            "        run: >-\n          # suppress the folded command\n"
            "          cargo test --locked -p marty-oid4vci"
        )
        self.assertEqual(workflow.count(original), 1)
        errors = check_release_contract.check_wasm_security_cache_setup(
            workflow.replace(original, replacement)
        )
        self.assertTrue(any("exact approved Cargo test script" in error for error in errors))

    def test_rejects_noop_wasm_test_runner(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        original = (
            "CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER: wasm-bindgen-test-runner"
        )
        self.assertEqual(workflow.count(original), 2)
        errors = check_release_contract.check_wasm_security_cache_setup(
            workflow.replace(original, "CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER: true")
        )
        self.assertEqual(
            sum("exact wasm-bindgen test runner" in error for error in errors), 2
        )

    def test_rejects_unpinned_wasm_test_runner_installer(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        original = "tool: wasm-bindgen-cli@0.2.126"
        self.assertEqual(workflow.count(original), 2)
        errors = check_release_contract.check_wasm_security_cache_setup(
            workflow.replace(original, "tool: wasm-bindgen-cli@0.2.125")
        )
        self.assertEqual(
            sum("must install the pinned wasm-bindgen" in error for error in errors), 2
        )

    def test_rejects_later_wasm_test_runner_replacement(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        original = "          tool: wasm-bindgen-cli@0.2.126\n"
        replacement = original + """      - name: Replace wasm-bindgen test runner
        uses: taiki-e/install-action@fcf5432d9f50d67e37ee6e29bdb7a224ff67b4a7
        with:
          tool: wasm-bindgen-cli@0.2.125
"""
        self.assertEqual(workflow.count(original), 2)
        errors = check_release_contract.check_wasm_security_cache_setup(
            workflow.replace(original, replacement, 1)
        )
        self.assertTrue(any("exact approved action sequence" in error for error in errors))

    def test_rejects_flow_style_runner_replacement(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        job_start = workflow.index("  crypto-wasm-security:")
        test_start = workflow.index(
            "      - name: Test browser key derivation and cleanup", job_start
        )
        replacement = (
            "      - { uses: taiki-e/install-action@"
            "fcf5432d9f50d67e37ee6e29bdb7a224ff67b4a7, with: { tool: "
            "wasm-bindgen-cli@0.2.125 } }\n"
        )
        workflow = workflow[:test_start] + replacement + workflow[test_start:]
        errors = check_release_contract.check_wasm_security_cache_setup(workflow)
        self.assertTrue(any("canonical block-style steps" in error for error in errors))

    def test_rejects_checkout_ref_override(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        original = "          persist-credentials: false\n"
        self.assertGreaterEqual(workflow.count(original), 2)
        errors = check_release_contract.check_wasm_security_cache_setup(
            workflow.replace(original, original + "          ref: main\n")
        )
        self.assertEqual(
            sum("exact approved action configuration" in error for error in errors), 2
        )

    def test_rejects_wasm_job_execution_overrides(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        job_start = workflow.index("  crypto-wasm-security:")
        job_end = workflow.index("\n  ci-gate:", job_start)
        job = workflow[job_start:job_end]
        mutations = (
            job.replace("    runs-on: ubuntu-latest", "    runs-on: self-hosted"),
            job.replace(
                "    runs-on: ubuntu-latest",
                "    runs-on: ubuntu-latest\n    container: attacker/image:latest",
            ),
            job.replace(
                "    runs-on: ubuntu-latest",
                "    runs-on: ubuntu-latest\n    services:\n      helper:\n"
                "        image: attacker/image:latest",
            ),
        )
        for mutated_job in mutations:
            with self.subTest(mutated_job=mutated_job.splitlines()[:6]):
                mutated = workflow[:job_start] + mutated_job + workflow[job_end:]
                errors = check_release_contract.check_wasm_security_cache_setup(
                    mutated
                )
                self.assertTrue(
                    any("exact approved job configuration" in error for error in errors)
                )

    def test_rejects_shell_injection_environment_overrides(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        runner = (
            "          CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER: "
            "wasm-bindgen-test-runner\n"
        )
        self.assertEqual(workflow.count(runner), 2)
        step_override = workflow.replace(
            runner, runner + "          BASH_ENV: .github/noop-cargo.sh\n", 1
        )
        step_errors = check_release_contract.check_wasm_security_cache_setup(
            step_override
        )
        self.assertTrue(
            any("exact approved test-step configuration" in error for error in step_errors)
        )

        self.assertEqual(workflow.count("\nenv:\n"), 1)
        workflow_override = workflow.replace(
            "\nenv:\n", "\nenv:\n  BASH_ENV: .github/noop-cargo.sh\n", 1
        )
        workflow_errors = check_release_contract.check_wasm_security_cache_setup(
            workflow_override
        )
        self.assertTrue(
            any("workflow shell-injection variable BASH_ENV" in error for error in workflow_errors)
        )

    def test_rejects_equivalent_root_shell_injection_keys(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(workflow.count("\nenv:\n"), 1)
        for injected_key in (
            "  BASH_ENV : .github/noop-cargo.sh\n",
            '  "BASH_ENV": .github/noop-cargo.sh\n',
        ):
            with self.subTest(injected_key=injected_key):
                mutated = workflow.replace("\nenv:\n", "\nenv:\n" + injected_key, 1)
                errors = check_release_contract.check_wasm_security_cache_setup(
                    mutated
                )
                self.assertTrue(
                    any("exact approved workflow environment" in error for error in errors)
                )
        for env_header in ("env :", '"env" :'):
            with self.subTest(env_header=env_header):
                mutated = workflow.replace("\nenv:\n", f"\n{env_header}\n", 1)
                errors = check_release_contract.check_wasm_security_cache_setup(
                    mutated
                )
                self.assertTrue(
                    any("exact approved workflow environment" in error for error in errors)
                )

    def test_rejects_bare_dash_hidden_runner_replacement(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        job_start = workflow.index("  crypto-wasm-security:")
        test_start = workflow.index(
            "      - name: Test browser key derivation and cleanup", job_start
        )
        hidden_step = """      - run: |
          # inert literal comment
      -
        { uses: taiki-e/install-action@fcf5432d9f50d67e37ee6e29bdb7a224ff67b4a7, with: { tool: wasm-bindgen-cli@0.2.125 } }
"""
        mutated = workflow[:test_start] + hidden_step + workflow[test_start:]
        errors = check_release_contract.check_wasm_security_cache_setup(mutated)
        self.assertTrue(any("canonical block-style steps" in error for error in errors))

    def test_rejects_custom_cargo_test_shell(self) -> None:
        pinned = (
            "mozilla-actions/sccache-action@"
            "fc920bf0ec8de6ee65d409111f7ec508035751ba"
        )
        workflow = f"""jobs:
  oid4vci-wasm-security:
    steps:
      - uses: {pinned}
      - run: cargo test --target wasm32-unknown-unknown
  crypto-wasm-security:
    steps:
      - uses: {pinned}
      - run: cargo test --target wasm32-unknown-unknown
        shell: bash {{0}}
"""
        errors = check_release_contract.check_wasm_security_cache_setup(workflow)
        self.assertTrue(any("failure-enforcing default shell" in error for error in errors))

    def test_rejects_workflow_and_job_default_shell_overrides(self) -> None:
        pinned = (
            "mozilla-actions/sccache-action@"
            "fc920bf0ec8de6ee65d409111f7ec508035751ba"
        )
        for workflow_defaults, job_defaults in (
            ("defaults:\n  run:\n    shell: bash {0}\n", ""),
            ("", "    defaults:\n      run:\n        shell: bash {0}\n"),
        ):
            with self.subTest(
                workflow_defaults=workflow_defaults, job_defaults=job_defaults
            ):
                workflow = f"""{workflow_defaults}jobs:
  oid4vci-wasm-security:
    steps:
      - uses: {pinned}
      - run: cargo test --target wasm32-unknown-unknown
  crypto-wasm-security:
{job_defaults}    steps:
      - uses: {pinned}
      - run: cargo test --target wasm32-unknown-unknown
"""
                errors = check_release_contract.check_wasm_security_cache_setup(
                    workflow
                )
                self.assertTrue(any("default shell" in error for error in errors))

    def test_rejects_tolerated_wasm_security_test_failures(self) -> None:
        pinned = (
            "mozilla-actions/sccache-action@"
            "fc920bf0ec8de6ee65d409111f7ec508035751ba"
        )
        for job_option, step_option in (
            ("    continue-on-error: true\n", ""),
            ("", "        continue-on-error: true\n"),
        ):
            with self.subTest(job_option=job_option, step_option=step_option):
                workflow = f"""jobs:
  oid4vci-wasm-security:
    steps:
      - uses: {pinned}
      - run: cargo test --target wasm32-unknown-unknown
  crypto-wasm-security:
{job_option}    steps:
      - uses: {pinned}
      - run: cargo test --target wasm32-unknown-unknown
{step_option}"""
                errors = check_release_contract.check_wasm_security_cache_setup(
                    workflow
                )
                self.assertTrue(any("must not tolerate" in error for error in errors))

    def test_rejects_escaped_yaml_mapping_keys(self) -> None:
        pinned = (
            "mozilla-actions/sccache-action@"
            "fc920bf0ec8de6ee65d409111f7ec508035751ba"
        )
        for escaped_property in (
            '      - "r\\u0075n": cargo test --target wasm32-unknown-unknown',
            '        "i\\u0066": false',
        ):
            with self.subTest(escaped_property=escaped_property):
                workflow = f"""jobs:
  oid4vci-wasm-security:
    steps:
      - uses: {pinned}
      - run: cargo test --target wasm32-unknown-unknown
  crypto-wasm-security:
    steps:
      - uses: {pinned}
{escaped_property}
      - run: cargo test --target wasm32-unknown-unknown
"""
                errors = check_release_contract.check_wasm_security_cache_setup(
                    workflow
                )
                self.assertTrue(
                    any("escaped YAML mapping keys" in error for error in errors)
                )

    def test_ignores_commented_cargo_before_wasm_security_cache(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        job_start = workflow.index("  crypto-wasm-security:")
        cache_start = workflow.index(
            "      - name: Enable compiler cache", job_start
        )
        comment_step = """      - run: |
          # cargo test is documentation, not an executed command
"""
        workflow = workflow[:cache_start] + comment_step + workflow[cache_start:]
        self.assertEqual(
            check_release_contract.check_wasm_security_cache_setup(workflow), []
        )


if __name__ == "__main__":
    unittest.main()
