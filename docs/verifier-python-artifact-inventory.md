# Verifier Python artifact inventory

The stable Core release assembles `marty-verification-py` wheels and an sdist
alongside the other Python packages. Before signing the assembled release
assets, `scripts/record_verifier_artifact_inventory.py` checks the existing
five-platform wheel matrix, the declared `cp311-abi3` tag, and one sdist,
binds their filenames and SHA-256 digests to the tag and commit, and emits
`marty-verification-python-artifact-inventory.json`. The existing release step
then signs and checksums this descriptor like the other assets. The script
does not rebuild or publish anything.

The macOS x86_64 matrix entry uses GitHub's standard Intel runner so the
existing wheel import probe runs natively. The macOS arm64 entry remains on
the standard ARM runner; no extra build job is added.

This is an **unqualified artifact inventory**, not a separate verifier product
pipeline or installed-product evidence. In particular, it does not prove that
`marty-verification` is published to crates.io (publishing is conditional),
that a clean project can install from a public channel, that the Python wheel
has a verification-only dependency closure, or that a headless executable runs
without network access. Those remain explicit qualification work.
