#!/usr/bin/env python3
"""Fetch the three private forks without giving compilation a source credential.

Run ``check`` in a separate, credential-free Actions step before ``fetch``. Only
the fetch step receives PRIVATE_FORKS_READ_TOKEN. This does not change Cargo's
home, target directory, or the later steps' network policy. Docker callers must
run the host check first and mount the token only for the fetch RUN instruction.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

CONSUMERS = {
    "ElevenID/marty-core", "ElevenID/marty-ui",
    "ElevenID/marty-verifier", "ElevenID/marty-credentials",
}
PRIVATE_FORKS = {
    "elevenid/isomdl-elevenid", "elevenid/ssi-elevenid", "elevenid/sd-jwt-rust",
}
CORE_PACKAGES = {
    "marty-crypto", "marty-verification", "marty-biometrics",
    "marty-secure-storage", "marty-types", "marty-oid4vci",
}
TOKEN_FILE = "/run/secrets/private_forks_read_token"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_context(env: dict[str, str], event: dict) -> None:
    repository = env.get("GITHUB_REPOSITORY", "")
    require(env.get("GITHUB_ACTIONS") == "true" and repository in CONSUMERS,
            "Private fork access is limited to the four ElevenID consumer workflows")
    require(event.get("repository", {}).get("full_name") == repository,
            "The event repository does not match this consumer")
    require(env.get("GITHUB_ACTOR", "").lower() != "dependabot[bot]"
            and env.get("GITHUB_TRIGGERING_ACTOR", "").lower() != "dependabot[bot]",
            "Dependabot runs do not receive private fork access")
    name, ref = env.get("GITHUB_EVENT_NAME"), env.get("GITHUB_REF", "")
    if name == "pull_request":
        pr = event.get("pull_request", {})
        require(pr.get("head", {}).get("repo", {}).get("full_name") == repository
                and pr.get("base", {}).get("repo", {}).get("full_name") == repository,
                "External pull requests need an owner-reviewed internal branch before native CI")
        require(pr.get("user", {}).get("login", "").lower() != "dependabot[bot]",
                "A human rerun does not authorize a Dependabot pull request")
        require(ref.startswith("refs/pull/") and ref.endswith("/merge"),
                "Native pull request CI must use the standard merge ref")
    elif name == "merge_group":
        group = event.get("merge_group", {})
        base = event.get("repository", {}).get("default_branch", "main")
        require(event.get("action") == "checks_requested"
                and group.get("base_ref") == "refs/heads/" + base
                and group.get("head_ref") == ref
                and ref.startswith("refs/heads/gh-readonly-queue/" + base + "/")
                and re.fullmatch(r"[0-9a-f]{40}", env.get("GITHUB_SHA", "")) is not None
                and group.get("head_sha") == env.get("GITHUB_SHA"),
                "Only the repository's admitted merge queue group may fetch private forks")
    elif name in {"schedule", "repository_dispatch"}:
        require(ref == "refs/heads/" + event.get("repository", {}).get("default_branch", "main"),
                "Scheduled and repository-dispatch builds must use the default branch")
    elif name in {"push", "workflow_dispatch"}:
        require(ref.startswith(("refs/heads/", "refs/tags/")),
                "Native builds require a repository branch or tag")
    else:
        raise ValueError("This event is not authorized to fetch private forks")


def check_context() -> None:
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    require(bool(event_path), "The GitHub Actions event is required")
    validate_context(dict(os.environ), json.loads(Path(event_path).read_text()))


def credential_response(operation: str, request: str, env: dict[str, str]) -> str:
    if operation != "get":
        return ""
    fields = dict(line.split("=", 1) for line in request.splitlines() if "=" in line)
    path = fields.get("path", "").lower().removesuffix(".git")
    if (fields.get("protocol") != "https"
            or fields.get("host", "").lower() != "github.com"
            or path not in PRIVATE_FORKS):
        return ""
    token_file = env.get("PRIVATE_FORKS_TOKEN_FILE")
    if token_file:
        require(token_file == TOKEN_FILE, "Unexpected Docker secret path")
        token = Path(token_file).read_text().rstrip("\r\n")
    else:
        token = env.get("PRIVATE_FORKS_READ_TOKEN", "")
    require(bool(token) and "\n" not in token and "\r" not in token,
            "Configure the private fork Contents-read credential")
    return "username=x-access-token\npassword=" + token + "\n\n"


def fetch_environment(token_file: str | None = None) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("GIT_CONFIG_", "GIT_TRACE"))}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="", SSH_ASKPASS="",
               CARGO_NET_GIT_FETCH_WITH_CLI="true", CARGO_NET_OFFLINE="false")
    helper = "!" + shlex.quote(Path(sys.executable).as_posix()) + " " + shlex.quote(
        Path(__file__).resolve().as_posix()) + " credential"
    settings = [("credential.helper", ""), ("credential.helper", helper),
                ("credential.useHttpPath", "true"), ("credential.interactive", "false"),
                ("core.hooksPath", "/dev/null"), ("http.followRedirects", "false")]
    env["GIT_CONFIG_COUNT"] = str(len(settings))
    for index, (key, value) in enumerate(settings):
        env[f"GIT_CONFIG_KEY_{index}"] = key
        env[f"GIT_CONFIG_VALUE_{index}"] = value
    if token_file:
        env["PRIVATE_FORKS_TOKEN_FILE"] = token_file
        env.pop("PRIVATE_FORKS_READ_TOKEN", None)
    else:
        env.pop("PRIVATE_FORKS_TOKEN_FILE", None)
    return env


def fetch(args: argparse.Namespace) -> None:
    if args.container:
        require(args.token_file == TOKEN_FILE and not os.environ.get("PRIVATE_FORKS_READ_TOKEN"),
                "Docker fetch requires only the mounted private_forks_read_token secret")
        require(Path(TOKEN_FILE).is_file() and Path(TOKEN_FILE).stat().st_size > 0,
                "The Docker source-reader secret is missing")
    else:
        require(not args.token_file, "Token files are only supported in Docker fetch mode")
        check_context()
        require(bool(os.environ.get("PRIVATE_FORKS_READ_TOKEN")),
                "Configure PRIVATE_FORKS_READ_TOKEN before enabling private forks")
    manifests = args.manifest_path or ["Cargo.toml"]
    for manifest in manifests:
        require(Path(manifest).is_file(), "The requested Cargo manifest does not exist")
    env = fetch_environment(args.token_file)
    try:
        if args.command == "update-core":
            require(not args.container and len(manifests) == 1,
                    "Core dependency updates require one host workspace")
            require(bool(args.package) and set(args.package) <= CORE_PACKAGES,
                    "Only the existing six public Core dependencies may be updated")
            command = ["cargo", "update", "--manifest-path", manifests[0]]
            for package in args.package:
                command.extend(["--package", package])
            subprocess.run(command, env=env, check=True)
        for manifest in manifests:
            subprocess.run(["cargo", "fetch", "--locked", "--manifest-path", manifest],
                           env=env, check=True)
    finally:
        env.pop("PRIVATE_FORKS_READ_TOKEN", None)
        env.pop("PRIVATE_FORKS_TOKEN_FILE", None)
        os.environ.pop("PRIVATE_FORKS_READ_TOKEN", None)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["check", "fetch", "update-core", "credential"])
    parser.add_argument("operation", nargs="?")
    parser.add_argument("--manifest-path", action="append")
    parser.add_argument("--package", action="append")
    parser.add_argument("--container", action="store_true")
    parser.add_argument("--token-file")
    args = parser.parse_args()
    if args.command == "credential":
        sys.stdout.write(credential_response(args.operation or "", sys.stdin.read(8192), dict(os.environ)))
    elif args.command == "check":
        require(not os.environ.get("PRIVATE_FORKS_READ_TOKEN"),
                "The trust check must run before the source credential is available")
        check_context()
    else:
        fetch(args)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        # Never include a command/environment dump or credential in a failure.
        print("::error::Private fork preparation failed: " + str(error), file=sys.stderr)
        sys.exit(1)
