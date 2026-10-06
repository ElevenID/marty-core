"""Guard the required Core preflight against test duplication and gate drift."""

import unittest
from pathlib import Path


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"
EUDI_TEST = "cargo test --locked -p marty-verification --features eudi-client --lib"


class PreflightPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.preflight = workflow.split("  preflight:\n", 1)[1].split(
            "  affected-tests:\n", 1
        )[0]
        cls.affected = workflow.split("  affected-tests:\n", 1)[1].split(
            "  zkp-native-security:\n", 1
        )[0]
        cls.gate = workflow.split("  ci-gate:\n", 1)[1]
        cls.workflow = workflow

    def test_eudi_client_runs_once_in_required_preflight(self) -> None:
        self.assertEqual(self.workflow.count(EUDI_TEST), 1)
        self.assertIn(EUDI_TEST, self.preflight)
        self.assertNotIn(EUDI_TEST, self.affected)
        self.assertIn("name: Fast Rust Preflight", self.preflight)
        self.assertIn(
            "cargo clippy --locked -p marty-verification --features eudi-client --all-targets -- -D warnings",
            self.preflight,
        )

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


if __name__ == "__main__":
    unittest.main()
