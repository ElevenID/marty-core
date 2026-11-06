"""Check the credential boundary and the release behavior that privacy changes."""

import ast
from pathlib import Path
import re
import unittest

from check_release_contract import _workflow_step_blocks

ROOT = Path(__file__).resolve().parents[1]
FETCH_JOBS = {
    "ci.yml": {"preflight", "kms-role-graphs", "rust-lint-compat", "affected-tests",
               "zkp-native-security", "platform-tests", "security", "feature-matrix",
               "feature-combinations", "python-tests", "python-conformance", "wasm-tests",
               "oid4vci-wasm-security", "crypto-wasm-security"},
    "license-compliance.yml": {"dependency-license-inventory", "sbom"},
    "mip-release-wallet.yml": {"release-wallet"},
    "release-wheel-preflight.yml": {"python-aarch64"},
    "release.yml": {"test", "build-crates", "build-python-wheels", "build-headless-verifier"},
}


def jobs(file: str) -> dict[str, str]:
    text = (ROOT / ".github/workflows" / file).read_text()
    text = text.split("\njobs:\n", 1)[1]
    starts = list(re.finditer(r"^  ([a-z][a-z0-9-]*):\n", text, re.M))
    return {match[1]: text[match.start(): starts[i + 1].start() if i + 1 < len(starts) else len(text)]
            for i, match in enumerate(starts)}


def release_condition(block: str, statuses: dict[str, str], private: bool, cancelled: bool = False) -> bool:
    expression = re.search(r"^    if: >-\n((?:      .+\n)+)", block, re.M)[1]
    expression = expression.replace("always()", "True").replace("!cancelled()", repr(not cancelled))
    expression = expression.replace("vars.ENABLE_PUBLIC_REGISTRY_PUBLISHING", "'true'")
    expression = expression.replace("vars.PRIVATE_FORKS_ENABLED", repr("true" if private else ""))
    expression = re.sub(r"needs\.([a-z-]+)\.result", lambda match: repr(statuses[match[1]]), expression)
    expression = " ".join(expression.split()).replace("&&", " and ").replace("||", " or ")
    tree = ast.parse(expression, mode="eval")
    allowed = (ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.Compare, ast.Eq, ast.Constant)
    if any(not isinstance(node, allowed) for node in ast.walk(tree)):
        raise AssertionError("Unexpected release condition syntax")
    return eval(compile(tree, "release-condition", "eval"), {"__builtins__": {}})


class PrivateForkWorkflowTests(unittest.TestCase):
    def test_all_source_readers_are_fetch_only_after_credential_free_check(self):
        for file, expected_jobs in FETCH_JOBS.items():
            observed = set()
            for name, block in jobs(file).items():
                steps = _workflow_step_blocks(block)
                reader_steps = [i for i, step in enumerate(steps) if "secrets.PRIVATE_FORKS_READ_TOKEN" in step]
                if not reader_steps:
                    continue
                observed.add(name)
                self.assertEqual(len(reader_steps), 1, (file, name))
                reader_index = reader_steps[0]
                reader = steps[reader_index]
                self.assertIn("if: vars.PRIVATE_FORKS_ENABLED == 'true'", reader)
                self.assertIn("run: python .github/scripts/private-forks.py fetch", reader)
                self.assertNotIn("continue-on-error", reader)
                self.assertEqual(block.count("secrets.PRIVATE_FORKS_READ_TOKEN"), 1)
                check = next(i for i, step in enumerate(steps) if "private-forks.py check" in step)
                self.assertLess(check, reader_index)
                self.assertNotIn("secrets.", steps[check])
                self.assertIn("'RUSTC_WRAPPER=' 'SCCACHE_GHA_ENABLED=false'", steps[check])
            self.assertEqual(observed, expected_jobs, file)

    def test_public_source_and_compiler_caches_are_disabled(self):
        for file in FETCH_JOBS:
            for name, block in jobs(file).items():
                for step in _workflow_step_blocks(block):
                    if re.search(r"uses: (actions/cache@|Swatinem/rust-cache@|mozilla-actions/sccache-action@)", step):
                        self.assertIn("if: vars.PRIVATE_FORKS_ENABLED != 'true'", step, (file, name))
        self.assertIn("    if: vars.PRIVATE_FORKS_ENABLED != 'true'", jobs("warm-ci-caches.yml")["rust"])

    def test_manylinux_uses_prepared_sources_without_a_reader(self):
        for file, name in (("release.yml", "build-python-wheels"), ("release-wheel-preflight.yml", "python-aarch64")):
            block = jobs(file)[name]
            action = next(step for step in _workflow_step_blocks(block) if "uses: PyO3/maturin-action@" in step)
            self.assertNotIn("secrets.", action)
            self.assertIn('--volume "{0}/git:/root/.cargo/git"', action)
            self.assertIn('--volume "{0}/registry:/root/.cargo/registry"', action)
            self.assertIn("'--locked --offline'", action)
            self.assertLess(block.index("private-forks.py fetch"), block.index("uses: PyO3/maturin-action@"))

    def test_private_mode_accepts_only_the_expected_sdist_skip(self):
        workflow = jobs("release.yml")
        self.assertIn("    if: vars.PRIVATE_FORKS_ENABLED != 'true'", workflow["build-python-sdists"])
        success = {name: "success" for name in ("build-crates", "build-headless-verifier", "build-python-wheels", "build-python-sdists")}
        for name in ("release", "publish-python"):
            self.assertTrue(release_condition(workflow[name], success, False))
            private = success | {"build-python-sdists": "skipped"}
            self.assertTrue(release_condition(workflow[name], private, True))
            self.assertFalse(release_condition(workflow[name], private, False))
            self.assertFalse(release_condition(workflow[name], private, True, cancelled=True))
            required = ("build-python-wheels",) if name == "publish-python" else ("build-crates", "build-headless-verifier", "build-python-wheels")
            for producer in required:
                for failure in ("failure", "cancelled", "skipped"):
                    self.assertFalse(release_condition(workflow[name], private | {producer: failure}, True), (name, producer, failure))
            self.assertFalse(release_condition(workflow[name], success | {"build-python-sdists": "failure"}, True))


if __name__ == "__main__":
    unittest.main()
