"""Generate an offline private-fork helper from an immutable Core revision.

Consumers retain their reviewed allowlist and denial message in
.github/scripts/private-forks.source.json. Run this canonical tool with
--consumer-root PATH --revision FULL_CORE_SHA; --check reproduces the pinned
artifact without changing files. No network requests or credentials are used.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ".github/scripts/private-forks.py"
REPOSITORY = "ElevenID/marty-core"


def source_bytes(root: Path, revision: str) -> bytes:
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("An immutable full Core revision is required")
    return subprocess.run(["git", "-C", str(root), "show", f"{revision}:{SOURCE}"],
                          check=True, capture_output=True).stdout


def render(raw: bytes, policy: dict, revision: str) -> bytes:
    consumers = policy["consumers"]
    denial = policy["denial"]
    if (not isinstance(consumers, list) or not consumers or
            any(not isinstance(value, str) or not re.fullmatch(r"ElevenID/[A-Za-z0-9_-]+", value)
                for value in consumers) or len(set(consumers)) != len(consumers)
            or not isinstance(denial, str) or not denial or "\n" in denial):
        raise ValueError("Invalid explicit consumer policy")
    source = raw.decode("utf-8")
    tree = ast.parse(source)
    assignment = next(node for node in tree.body if isinstance(node, ast.Assign)
                      and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "CONSUMERS")
    original_consumers = ast.literal_eval(assignment.value)
    validate = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == "validate_context")
    denial_node = validate.body[1].value.args[1]
    if not isinstance(denial_node, ast.Constant) or not isinstance(denial_node.value, str):
        raise ValueError("Canonical denial must remain a literal")
    # Keep independently reviewed helper digests unchanged. In particular, no
    # provenance header or generic runtime configuration is added to the helper.
    lines = source.splitlines(keepends=True)
    old_literal = ast.get_source_segment(source, denial_node)
    if denial_node.value != denial:
        line = lines[denial_node.lineno - 1]
        lines[denial_node.lineno - 1] = line.replace(old_literal, json.dumps(denial))
    if set(consumers) != original_consumers:
        if original_consumers <= set(consumers):
            extra = sorted(set(consumers) - original_consumers)
            lines.insert(assignment.end_lineno - 1,
                         "    " + ", ".join(json.dumps(value) for value in extra) + ",\n")
        else:
            lines[assignment.lineno - 1:assignment.end_lineno] = [
                "CONSUMERS = {\n" + "".join(f"    {json.dumps(value)},\n" for value in sorted(consumers)) + "}\n"]
    return "".join(lines).encode("utf-8")


def synchronize(root: Path, consumer: Path, revision: str | None, check: bool) -> None:
    manifest = consumer / ".github/scripts/private-forks.source.json"
    record = json.loads(manifest.read_text(encoding="utf-8"))
    if record["repository"] != REPOSITORY or record["path"] != SOURCE:
        raise ValueError("Unexpected canonical source")
    revision = revision or record["revision"]
    raw = source_bytes(root, revision)
    generated = render(raw, record["policy"], revision)
    expected = {**record, "revision": revision,
                "source_sha256": hashlib.sha256(raw).hexdigest(),
                "generated_sha256": hashlib.sha256(generated).hexdigest()}
    target = consumer / SOURCE
    if check:
        if record != expected or target.read_bytes().replace(b"\r\n", b"\n") != generated:
            raise ValueError("Pinned private-fork helper differs from canonical generation")
    else:
        target.write_bytes(generated)
        manifest.write_text(json.dumps(expected, indent=2) + "\n", encoding="utf-8", newline="\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--consumer-root", required=True, type=Path)
    parser.add_argument("--revision")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    synchronize(ROOT, args.consumer_root, args.revision, args.check)


if __name__ == "__main__":
    main()
