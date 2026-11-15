"""Guard the required Core preflight against test duplication and gate drift."""

import os
import re
import subprocess
import textwrap
import unittest
from pathlib import Path


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"
TRUST_LIST_TEST = "cargo test --locked -p marty-verification --features aamva-client,eudi-client --lib"


class PreflightPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.lint_compat = workflow.split("  rust-lint-compat:\n", 1)[1].split(
            "  affected-tests:\n", 1
        )[0]
        cls.affected = workflow.split("  affected-tests:\n", 1)[1].split(
            "  zkp-native-security:\n", 1
        )[0]
        cls.gate = workflow.split("  ci-gate:\n", 1)[1]
        cls.workflow = workflow

    def test_trust_list_clients_run_once_in_required_lint_job(self) -> None:
        self.assertEqual(self.workflow.count(TRUST_LIST_TEST), 1)
        self.assertIn(TRUST_LIST_TEST, self.lint_compat)
        self.assertNotIn(TRUST_LIST_TEST, self.affected)
        self.assertIn("name: Rust Lint and Compatibility", self.lint_compat)
        self.assertIn(
            "cargo clippy --locked -p marty-verification --features aamva-client,eudi-client --all-targets -- -D warnings",
            self.lint_compat,
        )
        self.assertIn("      - rust-lint-compat\n", self.gate)
        self.assertIn('test "$RUST_LINT_COMPAT" = success', self.gate)

    def test_root_change_still_runs_workspace_bindings_and_zkp(self) -> None:
        root_step = self.affected.split(
            "      - name: Test the workspace after root dependency changes\n", 1
        )[1].split("      - name: Test affected packages first\n", 1)[0]
        self.assertIn("if: steps.affected.outputs.all == 'true'", root_step)
        for command in (
            "cargo test --locked --workspace --exclude marty-zkp --exclude marty-bindings --features test-fixtures",
            "cargo test --locked -p marty-bindings --no-default-features",
            "cargo test --locked -p marty-zkp",
        ):
            with self.subTest(command=command):
                self.assertIn(command, root_step)

    def test_ci_gate_requires_preflight_success(self) -> None:
        self.assertIn("      - preflight\n", self.gate)
        self.assertIn("      - affected-tests\n", self.gate)
        self.assertIn("PREFLIGHT: ${{ needs.preflight.result }}", self.gate)
        self.assertIn("AFFECTED_TESTS: ${{ needs.affected-tests.result }}", self.gate)
        self.assertIn('test "$PREFLIGHT" = success', self.gate)
        self.assertIn('test "$AFFECTED_TESTS" = success', self.gate)

    def test_push_gate_requires_every_full_matrix_result(self) -> None:
        step = self.gate.split(
            "      - name: Require every applicable quality lane\n", 1
        )[1].split("      - name: Summarize CI performance\n", 1)[0]
        command = textwrap.dedent(step.split("        run: |\n", 1)[1])
        bindings = dict(re.findall(
            r"^      ([A-Z0-9_]+): \$\{\{ needs\.([a-z0-9-]+)\.result \}\}$",
            self.gate, re.MULTILINE,
        ))
        self.assertEqual(len(bindings), 14)
        successes = {name: "success" for name in bindings}
        successes["AFFECTED_TESTS"] = "skipped"

        def run(results: dict[str, str]) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                ["bash", "--noprofile", "--norc", "-c", command],
                env={"PATH": os.environ["PATH"], "EVENT_NAME": "push", **results},
                capture_output=True, text=True, timeout=5,
            )

        self.assertEqual(run(successes).returncode, 0)
        for name in bindings:
            rejected = ("success", "failure", "cancelled") if name == "AFFECTED_TESTS" else (
                "failure", "cancelled", "skipped",
            )
            for result in rejected:
                with self.subTest(job=bindings[name], result=result):
                    self.assertNotEqual(run(successes | {name: result}).returncode, 0)


if __name__ == "__main__":
    unittest.main()
