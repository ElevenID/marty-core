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

The native verifier wheel step additionally installs that locally built wheel
into a fresh virtual environment with package indexes disabled and dependency
resolution enabled. It stages the probe scripts, signed OB3 JSON vectors, and
a retained OB2 rejection fixture in a temporary consumer directory outside the
source checkout. It runs them with Python's isolated mode and requires the
package and native extension to resolve inside the fresh environment. From that
environment it repeats the native-extension import check and verifies the signed
OB3 fixture, a changed achievement name, and a mismatched Ed25519 issuer key.
The caller-time API is also exercised. The retired OB2 fixture must produce an
explicit retirement error, and neither the public package nor native extension
may expose OB2 issuance or verification APIs. These checks cover the selected
vectors and supplied key material; they do not authenticate caller-supplied
issuer documents or establish a complete trust policy.
Python's audit hook rejects audited socket operations during import and
verification; it does not sandbox native Rust network calls.
This provides local release-matrix wheel behavior evidence only. The earlier
build-runner import check still uses `--no-deps`; the fresh-environment check
will fail on unavailable declared Python requirements. It does not qualify
public-channel installability, undeclared or unexercised runtime dependencies,
native/system dependency closure, credential expiry, all verification formats,
or a standalone executable.
