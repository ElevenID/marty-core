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
    for path in normalized:
        if path.suffix != ".rs" and path.name != "Cargo.toml":
            continue
        matches = [
            (len(root.parts), name)
            for name, root in roots.items()
            if root == pathlib.PurePosixPath(".") or path.is_relative_to(root)
        ]
        if matches:
            directly_changed.add(max(matches)[1])

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
    return False, sorted(affected)


def git_changed_paths(base: str, head: str) -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--name-only", "--diff-filter=ACMRT", base, head],
        check=True,
        capture_output=True,
        text=True,
    )
    return [line for line in result.stdout.splitlines() if line]


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
