"""Security contracts for the fetch-only private dependency credential."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HELPER = Path(__file__).resolve().parents[1] / ".github/scripts/private-forks.py"
SPEC = importlib.util.spec_from_file_location("private_forks", HELPER)
private_forks = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(private_forks)


class PrivateForkAccessTests(unittest.TestCase):
    def context(self, name="pull_request"):
        env = {
            "GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "ElevenID/marty-core",
            "GITHUB_EVENT_NAME": name, "GITHUB_ACTOR": "owner", "GITHUB_TRIGGERING_ACTOR": "owner",
            "GITHUB_REF": "refs/pull/123/merge", "GITHUB_SHA": "a" * 40,
        }
        repo = {"full_name": "ElevenID/marty-core", "default_branch": "main"}
        event = {"repository": repo, "pull_request": {
            "head": {"repo": repo}, "base": {"repo": repo}, "user": {"login": "owner"},
        }}
        return env, event

    def test_same_repository_owner_pr_is_accepted(self):
        private_forks.validate_context(*self.context())

    def test_external_pr_is_denied_before_fetch(self):
        env, event = self.context()
        event["pull_request"]["head"]["repo"] = {"full_name": "outside/marty-core"}
        with self.assertRaises(ValueError):
            private_forks.validate_context(env, event)

    def test_dependabot_author_is_denied_even_when_human_reruns(self):
        env, event = self.context()
        event["pull_request"]["user"]["login"] = "dependabot[bot]"
        with self.assertRaises(ValueError):
            private_forks.validate_context(env, event)

    def test_dependabot_actor_and_triggering_actor_are_denied(self):
        for key in ("GITHUB_ACTOR", "GITHUB_TRIGGERING_ACTOR"):
            env, event = self.context()
            env[key] = "dependabot[bot]"
            with self.subTest(key=key), self.assertRaises(ValueError):
                private_forks.validate_context(env, event)

    def test_queue_requires_exact_generated_ref_and_sha(self):
        env, event = self.context("merge_group")
        env["GITHUB_REF"] = "refs/heads/gh-readonly-queue/main/pr-123-abc"
        event.update(action="checks_requested", merge_group={
            "base_ref": "refs/heads/main", "head_ref": env["GITHUB_REF"], "head_sha": env["GITHUB_SHA"],
        })
        private_forks.validate_context(env, event)
        for field in ("base_ref", "head_ref", "head_sha"):
            wrong = json.loads(json.dumps(event))
            wrong["merge_group"][field] = "wrong"
            with self.subTest(field=field), self.assertRaises(ValueError):
                private_forks.validate_context(env, wrong)

    def test_dispatch_schedule_and_push_event_boundaries(self):
        for name in ("push", "workflow_dispatch", "schedule", "repository_dispatch"):
            env, event = self.context(name)
            env["GITHUB_REF"] = "refs/heads/main"
            private_forks.validate_context(env, event)
        env["GITHUB_EVENT_NAME"] = "pull_request_target"
        with self.assertRaises(ValueError):
            private_forks.validate_context(env, event)
        env["GITHUB_EVENT_NAME"] = "repository_dispatch"
        env["GITHUB_REF"] = "refs/heads/unreviewed"
        with self.assertRaises(ValueError):
            private_forks.validate_context(env, event)

    def test_real_git_credential_protocol_scopes_all_three_forks(self):
        with patch.dict(os.environ, {"PRIVATE_FORKS_READ_TOKEN": "test-reader-value"}):
            env = private_forks.fetch_environment()
        for path in private_forks.PRIVATE_FORKS:
            for suffix in ("", ".git"):
                request = f"protocol=https\nhost=github.com\npath={path}{suffix}\n\n"
                run = subprocess.run(["git", "credential", "fill"], input=request,
                                     text=True, capture_output=True, env=env, check=True)
                self.assertIn("password=test-reader-value", run.stdout)
        for url in ("http://github.com/ElevenID/ssi-elevenid", "https://other.test/ElevenID/ssi-elevenid",
                    "https://github.com/ElevenID/marty-core", "https://github.com/ElevenID/ssi-elevenid-extra",
                    "https://github.com/ElevenID/ssi-elevenid/subpath"):
            run = subprocess.run(["git", "credential", "fill"], input=f"url={url}\n\n",
                                 text=True, capture_output=True, env=env)
            self.assertNotEqual(run.returncode, 0)
            self.assertNotIn("test-reader-value", run.stdout + run.stderr)

    def test_docker_token_is_read_only_for_allowed_get(self):
        env = {"PRIVATE_FORKS_TOKEN_FILE": private_forks.TOKEN_FILE}
        allowed = "protocol=https\nhost=github.com\npath=ElevenID/ssi-elevenid\n\n"
        with patch.object(Path, "read_text", return_value="docker-reader\n") as read:
            self.assertEqual(private_forks.credential_response("store", allowed, env), "")
            self.assertEqual(private_forks.credential_response("get", allowed.replace("github.com", "evil.test"), env), "")
            read.assert_not_called()
            self.assertIn("password=docker-reader", private_forks.credential_response("get", allowed, env))
            read.assert_called_once()

    def test_fetch_has_token_only_in_child_environment_and_preserves_cargo_paths(self):
        env, event = self.context()
        with tempfile.TemporaryDirectory() as directory:
            event_path = Path(directory) / "event.json"
            event_path.write_text(json.dumps(event))
            manifest = Path(directory) / "Cargo.toml"
            manifest.write_text("[workspace]\n")
            env.update(GITHUB_EVENT_PATH=str(event_path), PRIVATE_FORKS_READ_TOKEN="test-reader-value",
                       CARGO_HOME="existing-cargo", CARGO_TARGET_DIR="existing-target", CARGO_NET_OFFLINE="true")
            observed = []

            def run(command, *, env, check):
                observed.append((command, dict(env)))

            args = argparse.Namespace(command="fetch", container=False, token_file=None,
                                      manifest_path=[str(manifest)], package=None)
            with patch.dict(os.environ, env, clear=True), patch.object(subprocess, "run", side_effect=run):
                private_forks.fetch(args)
                self.assertNotIn("PRIVATE_FORKS_READ_TOKEN", os.environ)
                self.assertEqual(os.environ["CARGO_NET_OFFLINE"], "true")
            command, child = observed[0]
            self.assertEqual(command, ["cargo", "fetch", "--locked", "--manifest-path", str(manifest)])
            self.assertEqual(child["PRIVATE_FORKS_READ_TOKEN"], "test-reader-value")
            self.assertEqual(child["CARGO_HOME"], "existing-cargo")
            self.assertEqual(child["CARGO_TARGET_DIR"], "existing-target")
            self.assertEqual(child["CARGO_NET_OFFLINE"], "false")
            self.assertEqual(child["GIT_CONFIG_GLOBAL"], os.devnull)
            self.assertFalse(any("test-reader-value" in str(value) for key, value in child.items()
                                 if key.startswith("GIT_CONFIG_")))
            self.assertEqual(sorted(p.name for p in Path(directory).iterdir()), ["Cargo.toml", "event.json"])

    def test_missing_reader_fails_before_cargo(self):
        env, event = self.context()
        with tempfile.TemporaryDirectory() as directory:
            event_path = Path(directory) / "event.json"
            event_path.write_text(json.dumps(event))
            env["GITHUB_EVENT_PATH"] = str(event_path)
            args = argparse.Namespace(command="fetch", container=False, token_file=None,
                                      manifest_path=None, package=None)
            with patch.dict(os.environ, env, clear=True), patch.object(subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "Configure PRIVATE_FORKS_READ_TOKEN"):
                    private_forks.fetch(args)
                run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
