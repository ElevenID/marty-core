# Marty headless offline verifier

This Ubuntu 24.04 amd64 command line program verifies Open Badges 3 credentials
without a Marty server, database, Redis, issuer key, or Canvas installation.
It uses the same `marty-verification` Rust proof, issuer authorization, and
status kernel as other Marty consumers. This is a **preview** profile; it is
not a general mDL, eMRTD, kiosk, or network presentation verifier.
Other Linux distributions and architectures are not qualified by this bundle.

## Trust and status contract

An operator installs a local JSON trust profile and obtains its SHA-256 digest
through a separate trusted channel. The command rejects a changed profile.
The profile pins the issuer ID, verification documents, and the decision to
accept credentials with no status reference. Credential-supplied documents
cannot replace these pinned documents. The command also rejects future
`validFrom` and expired `validUntil` timestamps when present.

Status references fail closed because this initial offline profile does not
admit authenticated, fresh status-list snapshots. The shared verification
kernel reports the status-authority failure. `allow_credentials_without_status`
must be set explicitly in the trust profile; it does not override a present
status reference. An operator should only set it when their policy accepts
credentials that do not declare a revocation mechanism.

## Reproducible local consumer run

For a version-pinned external preview using Docker, see
[EXTERNAL_PREVIEW_V0.2.2.md](EXTERNAL_PREVIEW_V0.2.2.md). To run a release
directly on a qualified Linux host, download its
`marty-headless-verify-<version>-linux-amd64.tar.gz` asset and `SHA256SUMS`
from the same release. Verify the checksum and GitHub provenance attestation,
then extract the binary and samples on a Linux amd64 machine. This asset is
not present in v0.2.0.

```bash
version=REPLACE_WITH_RELEASE_VERSION
gh release download "v$version" --repo ElevenID/marty-core \
  --pattern "marty-headless-verify-$version-linux-amd64.tar.gz" \
  --pattern SHA256SUMS
grep -F "  ./marty-headless-verify-$version-linux-amd64.tar.gz" SHA256SUMS \
  | sha256sum --check -
gh attestation verify "marty-headless-verify-$version-linux-amd64.tar.gz" \
  --repo ElevenID/marty-core
tar -xzf "marty-headless-verify-$version-linux-amd64.tar.gz"
cd "marty-headless-verify-$version-linux-amd64"
./bin/marty-headless-verify verify \
  --credential samples/ob3-valid.json \
  --trust-profile samples/demo-trust-profile.json \
  --trust-sha256 8a0fd4579fbf239f54598ea06b986e1bd70bae1549b7e3942ac2c4a05b95980e
```

Alternatively, build from the matching
`marty-core-workspace-<version>.tar.gz` source bundle:

```bash
version=REPLACE_WITH_RELEASE_VERSION
tar -xzf "marty-core-workspace-$version.tar.gz"
cd "marty-core-$version"
cargo build --locked --release -p marty-headless-verifier
sha256sum marty-headless-verifier/samples/demo-trust-profile.json
./target/release/marty-headless-verify verify \
  --credential marty-headless-verifier/samples/ob3-valid.json \
  --trust-profile marty-headless-verifier/samples/demo-trust-profile.json \
  --trust-sha256 8a0fd4579fbf239f54598ea06b986e1bd70bae1549b7e3942ac2c4a05b95980e
```

The sample trust digest above is for the checked-in synthetic profile only.
For real trust, the profile and its pinned digest must be provided by the
operator through their own approval process. A positive result has exit code
0, a denial has exit code 2, and input or configuration errors use exit code
1. The JSON result includes the shared kernel decision and reason codes.

The signed example and trust profile are synthetic public test material. Edit
the credential's achievement name to see a proof failure. Change
`trusted_issuer` to see a trust denial; recompute and pass the resulting
profile digest for that negative test. Add a `credentialStatus` reference to
see an unavailable offline status authority denied.
