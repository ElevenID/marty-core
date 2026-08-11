from __future__ import annotations

import unittest

import stable_tag_gate


COMMIT = "a" * 40
TAG_OBJECT = "b" * 40
POLICY = {
    "schema": stable_tag_gate.SCHEMA,
    "required_workflows": [
        {"path": ".github/workflows/ci.yml", "event": "push"},
        {"path": "dynamic/github-code-scanning/codeql", "event": "dynamic"},
    ],
}


def run(
    run_id: int,
    path: str,
    event: str,
    *,
    status: str = "completed",
    conclusion: str | None = "success",
    head_sha: str = COMMIT,
) -> dict[str, object]:
    return {
        "id": run_id,
        "path": path,
        "event": event,
        "status": status,
        "conclusion": conclusion,
        "head_sha": head_sha,
    }


class WorkflowGateTests(unittest.TestCase):
    def payload(self) -> dict[str, object]:
        return {
            "workflow_runs": [
                run(10, ".github/workflows/ci.yml", "push"),
                run(11, "dynamic/github-code-scanning/codeql", "dynamic"),
            ]
        }

    def test_terminal_exact_head_workflows_pass(self) -> None:
        accepted = stable_tag_gate.validate_workflow_runs(
            self.payload(), POLICY, COMMIT, 99
        )
        self.assertEqual([item["run_id"] for item in accepted], [10, 11])

    def test_pending_workflow_blocks_tag_preparation(self) -> None:
        payload = self.payload()
        payload["workflow_runs"][0]["status"] = "in_progress"
        payload["workflow_runs"][0]["conclusion"] = None
        with self.assertRaisesRegex(stable_tag_gate.StableTagGateError, "pending"):
            stable_tag_gate.validate_workflow_runs(payload, POLICY, COMMIT, 99)

    def test_failed_workflow_blocks_tag_preparation(self) -> None:
        payload = self.payload()
        payload["workflow_runs"][0]["conclusion"] = "failure"
        with self.assertRaisesRegex(stable_tag_gate.StableTagGateError, "did not succeed"):
            stable_tag_gate.validate_workflow_runs(payload, POLICY, COMMIT, 99)

    def test_missing_and_different_head_workflows_block(self) -> None:
        payload = self.payload()
        payload["workflow_runs"][0]["head_sha"] = "c" * 40
        with self.assertRaisesRegex(stable_tag_gate.StableTagGateError, "missing"):
            stable_tag_gate.validate_workflow_runs(payload, POLICY, COMMIT, 99)

    def test_latest_rerun_is_authoritative(self) -> None:
        payload = self.payload()
        payload["workflow_runs"].extend(
            [
                run(20, ".github/workflows/ci.yml", "push", conclusion="failure"),
                run(21, ".github/workflows/ci.yml", "push"),
            ]
        )
        accepted = stable_tag_gate.validate_workflow_runs(payload, POLICY, COMMIT, 99)
        self.assertEqual(accepted[0]["run_id"], 21)


class ReleaseProofTests(unittest.TestCase):
    def evidence(self) -> dict[str, object]:
        return {
            "schema": stable_tag_gate.SCHEMA,
            "repository": "ElevenID/marty-core",
            "tag": "v1.2.3",
            "source_sha": COMMIT,
            "preparation_run_id": 42,
            "required_workflows": [{"path": "ci", "run_id": 10}],
            "tag_object_sha": TAG_OBJECT,
            "peeled_source_sha": COMMIT,
        }

    def prep_run(self) -> dict[str, object]:
        return {
            "id": 42,
            "path": stable_tag_gate.PREPARATION_WORKFLOW,
            "event": "workflow_dispatch",
            "head_sha": COMMIT,
            "head_branch": "main",
            "status": "completed",
            "conclusion": "success",
        }

    def message(self) -> str:
        return (
            "Release 1.2.3\n\n"
            f"Stable-Tag-Gate: {stable_tag_gate.SCHEMA}\n"
            "Preparation-Run: 42\n"
            f"Source-SHA: {COMMIT}\n"
        )

    def test_annotated_exact_preparation_proof_passes(self) -> None:
        stable_tag_gate.validate_release_proof(
            "ElevenID/marty-core",
            "v1.2.3",
            COMMIT,
            "tag",
            TAG_OBJECT,
            self.message(),
            self.prep_run(),
            self.evidence(),
        )

    def test_lightweight_tag_is_rejected_without_mutation(self) -> None:
        with self.assertRaisesRegex(stable_tag_gate.StableTagGateError, "annotated"):
            stable_tag_gate.validate_release_proof(
                "ElevenID/marty-core",
                "v1.2.3",
                COMMIT,
                "commit",
                TAG_OBJECT,
                self.message(),
                self.prep_run(),
                self.evidence(),
            )

    def test_wrong_run_or_evidence_is_rejected(self) -> None:
        bad_run = self.prep_run()
        bad_run["conclusion"] = "failure"
        with self.assertRaises(stable_tag_gate.StableTagGateError):
            stable_tag_gate.validate_release_proof(
                "ElevenID/marty-core",
                "v1.2.3",
                COMMIT,
                "tag",
                TAG_OBJECT,
                self.message(),
                bad_run,
                self.evidence(),
            )


if __name__ == "__main__":
    unittest.main()
