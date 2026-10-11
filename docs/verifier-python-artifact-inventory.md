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

The native wheel import step also runs a bounded, headless **in-process**
consumer probe against signed Open Badges 2/3 fixtures, an OB2 changed-assertion-ID
case, and an OB3 changed-achievement-name case. The former OB2 assertion-ID
binding gap is now covered by an active typed Rust regression test and by this
local-wheel consumer probe. These checks do not prove every signed-payload
field is bound or authenticate the caller-supplied `document_store`: an OB2
`valid: true` result remains relative to the issuer and key records supplied
by the caller, which must be authenticated by that caller.
Python's audit hook rejects audited socket operations during import and
verification; it does not sandbox native Rust network calls.
This provides local release-matrix wheel behavior evidence only: the wheel is
installed with `--no-deps` into the build runner, not a clean environment, and
the probe does not qualify public-channel installability, dependency closure,
all verification formats, or a standalone executable.
