# Native build access

Core keeps its existing Git dependencies on `ElevenID/isomdl-elevenid`,
`ElevenID/ssi-elevenid`, and `ElevenID/sd-jwt-rust`. Making those complete
repositories private does not require replacement crates, new Git URLs, or
different lockfile pins. Their upstream history and license notices remain.

## Existing CI with a private source reader

Set the repository Actions secret `PRIVATE_FORKS_READ_TOKEN` to a credential
with **Contents: read** for only those three repositories. The repository
Actions variable `PRIVATE_FORKS_ENABLED=true` activates the authenticated path.
An unset or `false` variable retains the existing anonymous build behavior.
The code does not change either setting or repository visibility.

Native jobs first run `.github/scripts/private-forks.py check` without the
reader. A separate fetch step receives the reader, runs `cargo fetch --locked`,
and exits before compilation or tests. The Git credential helper only answers
HTTPS requests for the exact three repository paths on `github.com`. It is
configured through process environment variables; credentials are never
written to Git configuration, clone URLs, Cargo configuration, or artifacts.

Builds and tests retain their existing commands, gates, and public runner
capacity. Ordinary host builds may still download public tools and runtime
binaries after fetching dependencies. The private source reader is absent
from those later steps. Native cache warming, Cargo Git/target caches, and
sccache are disabled when private access is enabled. They must not be restored
or exported from public workflows after the cutover.

## Who may run native jobs

Same-repository pull requests, repository branch/tag builds, and dispatches
use the consumer's normal write-access boundary. External pull requests and
Dependabot runs, including human reruns of Dependabot-authored PRs, fail the
credential-free check. An owner can review and import a contribution into an
internal branch before running native validation. Source-only checks remain
available to outside contributions.

Merge-group runs must match GitHub's generated queue ref, exact group SHA, and
default-branch base. The existing required reviews, native checks, and queue
admission policy remain in force. Scheduled and repository-dispatch runs use
the default branch. Unsupported event types, including `pull_request_target`,
are rejected.

Anyone permitted to change and run an internal workflow can access its fetched
dependencies, even after the credential has been removed. Grant that authority
only to people who may read the three forks. Public compiler diagnostics may
contain paths, symbols, or snippets; this model keeps complete dependency
repositories and source caches private while retaining public CI.

## Wheels and releases

Linux wheel jobs fetch on the host, then mount only the prepared Cargo `git`
and `registry` directories into the pinned Maturin action's manylinux container.
Maturin compiles with `--locked --offline` and receives no source reader.
Windows and macOS wheels use the same fetched Cargo graph. All existing wheel
import checks, clean-consumer checks, signing, checksums, and provenance remain.

Maturin source distributions can vendor Git dependencies. Therefore private
mode suppresses the sdist producer and its download. The Python and GitHub
release gates accept that specific expected skip only when private mode is
enabled; every required binary producer must still succeed. The verifier
inventory requires all five wheels and forbids an sdist in private mode.
The public Core source archive remains a `git archive` of tracked Core files,
without vendored dependencies. Dependency inventories and SBOMs describe the
resolved graph without packaging its source.

Public registry publishing remains a separate opt-in and is not enabled by
this change. Private mode prevents crates.io source publishing. If PyPI
publishing is separately enabled, it publishes the verified wheels only.

## Activation and local development

Merge these changes before activating the variable, configure the scoped
reader, and verify the authenticated native and wheel jobs during the
coordinated visibility cutover. Keep the variable enabled once dependencies
are private: turning it off restores anonymous fetching, not access.

Authorized local builds use the same Git URLs and lockfiles with the
developer's normal private-repository read access. The optional manual
[`marty-commercial-rust` coordinator](https://github.com/ElevenID/marty-commercial-rust)
is available for private validation; it is not required to replace the public
CI Gate, merge queue, or release workflows.

Continue upstream updates through each fork's existing sync workflow and
resolve actual merge conflicts in its update PR. Preserve the SD-JWT sync
marker and SSI's separate linked-data lineage. Keep all required upstream
license and attribution files when distributing compiled products.
