from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
from collections import defaultdict, deque


ROOT_INVALIDATORS = {
    "Cargo.lock",
    "Cargo.toml",
    "rust-toolchain.toml",
}

# Cargo metadata cannot express test-source imports across workspace packages.
# Crypto's JWK integration test embeds this Verification-owned contract directly.
# This is a test-only edge, not a library change: its Cargo consumers need not
# be added to the reverse dependency closure solely because the vector changes.
CROSS_PACKAGE_TEST_INPUT_OWNERS = {
    "marty-verification/tests/fixtures/public_key_jwk_vectors.json": {"marty-crypto"},
}


def affected_packages(
    changed_paths: list[str], metadata: dict[str, object]
) -> tuple[bool, list[str]]:
    normalized = [pathlib.PurePosixPath(path.replace("\\", "/")) for path in changed_paths]
    if any(str(path) in ROOT_INVALIDATORS or path.parts[:1] == (".cargo",) for path in normalized):
        return True, []

    packages = metadata.get("packages", [])
    workspace_members = set(metadata.get("workspace_members", []))
    workspace = [package for package in packages if package["id"] in workspace_members]
    roots = {
        package["name"]: pathlib.PurePosixPath(
            pathlib.Path(package["manifest_path"]).parent.relative_to(pathlib.Path.cwd()).as_posix()
        )
        for package in workspace
    }

    directly_changed: set[str] = set()
    extra_test_packages: set[str] = set()
    for path in normalized:
        # Fixtures, native sources, and embedded documentation are build/test
        # inputs too. Package ownership, not the extension, defines relevance.
        matches = [
            (len(root.parts), name)
            for name, root in roots.items()
            if root == pathlib.PurePosixPath(".") or path.is_relative_to(root)
        ]
        if matches:
            directly_changed.add(max(matches)[1])
            extra_owners = CROSS_PACKAGE_TEST_INPUT_OWNERS.get(str(path), set())
            if not extra_owners <= set(roots):
                # A mapped package disappearing is not evidence that its test
                # obligation vanished. Keep the workspace fallback.
                return True, []
            extra_test_packages.update(extra_owners)
        else:
            # Shared scripts/configuration and removed packages have no proven
            # owner in current metadata. Never turn uncertainty into no tests.
            return True, []

    reverse_dependencies: dict[str, set[str]] = defaultdict(set)
    workspace_names = set(roots)
    for package in workspace:
        for dependency in package.get("dependencies", []):
            dependency_name = dependency.get("name")
            if dependency_name in workspace_names:
                reverse_dependencies[dependency_name].add(package["name"])

    affected = set(directly_changed)
    queue = deque(directly_changed)
    while queue:
        dependency = queue.popleft()
        for consumer in reverse_dependencies[dependency]:
            if consumer not in affected:
                affected.add(consumer)
                queue.append(consumer)
    affected.update(extra_test_packages)
    return False, sorted(affected)


def git_changed_paths(base: str, head: str) -> list[str]:
    result = subprocess.run(
        # Disable rename folding so both the old and new package are selected.
        # NUL delimiters preserve spaces/unicode and avoid Git's quoted paths.
        ["git", "diff", "--name-only", "-z", "--no-renames", base, head, "--"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return [path for path in result.stdout.split("\0") if path]


def cargo_metadata() -> dict[str, object]:
    result = subprocess.run(
        ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    args = parser.parse_args()

    all_packages, packages = affected_packages(
        git_changed_paths(args.base, args.head), cargo_metadata()
    )
    output = pathlib.Path(os.environ["GITHUB_OUTPUT"])
    with output.open("a", encoding="utf-8") as stream:
        stream.write(f"all={'true' if all_packages else 'false'}\n")
        stream.write(f"packages={' '.join(packages)}\n")
        stream.write(f"has_packages={'true' if packages else 'false'}\n")
    print("all workspace packages" if all_packages else " ".join(packages) or "no Rust packages")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
