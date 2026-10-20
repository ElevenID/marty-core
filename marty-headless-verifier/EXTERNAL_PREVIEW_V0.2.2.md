# External preview: offline OB3 verifier v0.2.2

This is a **preview test**, not a supported product qualification. Use only the
synthetic credential and trust profile in the public release. No Marty account,
server, database, issuer key, Canvas instance, or maintainer-provided secret is
needed. The target is Linux amd64; the instructions below use Docker's Linux
container mode and do not give the verifier network access.

The verifier checks an Open Badges 3 signed credential against an
operator-pinned local trust profile. It does not support network presentations,
status-list retrieval, mDL, eMRTD, or kiosk operation. A credential with a
status reference is denied because authenticated fresh offline status snapshots
are not yet supported. The sample trust profile is synthetic and must not be
used to decide whether a real-world issuer or credential is trustworthy.

## Run the public asset

Prerequisites: Docker with Linux amd64 containers, `curl`, `sha256sum`, `tar`,
and GitHub CLI on the host. Sign in to GitHub CLI with **your own** GitHub
account before starting; attestation lookup currently requires login, but no
Marty credentials or private-repository access. Run these commands in a new
empty directory on a Linux shell. The asset downloads themselves are anonymous
and use only the v0.2.2 public release.

```bash
set -euo pipefail
base=https://github.com/ElevenID/marty-core/releases/download/v0.2.2
asset=marty-headless-verify-0.2.2-linux-amd64.tar.gz
curl -fL "$base/$asset" -o "$asset"
curl -fL "$base/SHA256SUMS" -o SHA256SUMS
grep -F "  ./$asset" SHA256SUMS | sha256sum --check -
gh attestation verify "$asset" --repo ElevenID/marty-core
tar -xzf "$asset"
bundle="$(pwd)/marty-headless-verify-0.2.2-linux-amd64"
docker run --rm --network none --platform linux/amd64 \
  --mount "type=bind,src=$bundle,dst=/bundle,readonly" \
  ubuntu:24.04 /bundle/bin/marty-headless-verify verify \
  --credential /bundle/samples/ob3-valid.json \
  --trust-profile /bundle/samples/demo-trust-profile.json \
  --trust-sha256 8a0fd4579fbf239f54598ea06b986e1bd70bae1549b7e3942ac2c4a05b95980e
```

Expected: exit code 0 and JSON containing `"accepted":true`. The checksum
line must report `OK`. The Docker container has no network, and the extracted
bundle is mounted read-only. Docker may download the public Ubuntu image
*before* starting that offline container.

If checksum or attestation verification fails, stop; do not run the bundle.
Do not report an unverified download as a passing preview. The archive also
contains `acceptance.sh`, which exercises signed acceptance and tampered-proof,
wrong-trust, expired, status-reference, and wrong-pin denials on an Ubuntu
24.04 amd64 host with `jq`. That suite was run by maintainers; the Docker
smoke above deliberately asks an external tester to check the clean public
download and isolated execution path, not to repeat every qualification case.

## Report the result

The Core release maintainer triages preview reports through the
[public issue tracker](https://github.com/ElevenID/marty-core/issues/new).
Use a title beginning `Verifier preview v0.2.2` and include:

- Linux/Docker version and CPU architecture;
- whether anonymous download, checksum, attestation, and Docker verification
  each passed; include the exit code and a redacted error if not;
- approximate elapsed time and any instructions that needed interpretation;
- whether the test used the unchanged synthetic files.

Never post real credentials, private trust profiles, access tokens, personal
data, or full environment dumps in a public issue. If a report cannot be
sanitized, ask the maintainer for a private reporting channel first. A clean
tester run is valuable usability evidence, but it does not by itself qualify
the broader offline library, provisioning, restart, replay, rollback, or a
supported self-host installation.
