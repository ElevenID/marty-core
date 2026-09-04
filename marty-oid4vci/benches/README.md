# mdoc issuance preparation benchmark

`mdoc_issuance` measures Marty's public remote-signing preparation route with
1, 8, 32, 128, and 512 issued elements. Each element has a deterministic
256-byte value. A preflight assembles and decodes every fixture, then checks
the reserved credential ID, namespace and item counts, sequential digest IDs,
SHA-256 algorithm, and every tag-24 `IssuerSignedItemBytes` commitment before
timing begins.

The same benchmark also compares a caller-side sequential loop with Marty's
single-call remote mdoc batch preparation for 1, 8, 32, and 256 credentials.
Each credential contains eight deterministic 256-byte elements and has unique
routing and reserved credential identities. Batch preflight checks caller
order and fully assembles and decodes every prepared result before timing.

The timed region includes request validation, salts, JSON-to-CBOR conversion,
item and tag-24 encoding, serial SHA-256 commitments, MSO construction, holder
binding, and COSE signing-input preparation. Request cloning, Python/FFI work,
signing or KMS latency, final assembly, and base64 transport encoding are
outside the timed region.

The batch route remains scalar: it plans all credentials in caller order and
submits their item commitments to one `SerialDigestExecutor` call. These
measurements establish batching overhead and credential throughput; they do
not enable the optional parallel executor or change any production threshold.

Run a smoke check with:

```console
cargo test --locked -p marty-oid4vci --bench mdoc_issuance
```

Collect measurements with:

```console
cargo bench --locked -p marty-oid4vci --bench mdoc_issuance -- --noplot
```

For revision comparisons, use an otherwise quiet machine, separate Cargo
target directories, and a shared fresh Criterion output directory. Run both
baseline-to-candidate and candidate-to-baseline orderings. Report median
estimates, 95% confidence intervals, element throughput for scalar fixtures,
and credential throughput for batch fixtures. These results are an
issuance-preparation baseline, not an isolated SHA benchmark, and do not by
themselves authorize a parallel route or production threshold.

## Opt-in mdoc issuance payload matrix

The mdoc payload matrix is disabled unless `MARTY_MDOC_MATRIX=1`. With the
matrix variables unset, `mdoc_issuance` retains every historical group,
benchmark ID, fixture, preflight, sample size, warm-up, measurement period,
significance level, and noise threshold. Enabling the matrix adds this separate
ID space:

```text
mdoc_issuance_payload_matrix/{class}/n={item_count}/scalar
mdoc_issuance_payload_matrix/{class}/n={item_count}/sequential/b={batch_size}
mdoc_issuance_payload_matrix/{class}/n={item_count}/batch/b={batch_size}
```

The supported dimensions and selector environment variables are:

- `MARTY_MDOC_MATRIX_CLASSES`: `small_primitive`, `medium_nested`,
  `large_portrait`, `mixed_size`
- `MARTY_MDOC_MATRIX_ITEM_COUNTS`: `1`, `8`, `32`, `128`, `512`
- `MARTY_MDOC_MATRIX_BATCH_SIZES`: `1`, `8`, `32`, `256`

Each selector accepts a comma-separated subset, `all`, or may be omitted to
select every value. Whitespace around tokens is allowed. Unknown, empty,
non-Unicode, duplicate, noncanonical numeric, and `all`-combined selections
fail before any fixture is built. Selectors are ignored while the matrix is
disabled.

Fixtures contain deterministic, non-personal semantic values. Small fixtures
cycle through primitive integers, booleans, text, and nulls; the `n=1` case
contains only the initial integer. Medium fixtures contain nested maps and
arrays. Each large-portrait credential contains exactly one 256-KiB text value;
when present, its remaining claims are small. Mixed fixtures start with one
bounded 64-KiB value, then add nested values, integers, small text, and bounded
1-KiB values as the selected item count permits; the `n=1` case contains only
the 64-KiB value. Every credential and batch route has a unique deterministic
identity.
Fixture construction occurs before measurement, and request cloning occurs in
Criterion's untimed per-iteration setup.

Before measurement, every selected scalar, sequential, and batch case passes
through the public remote mdoc preparation APIs, public assembly, and typed CBOR
decode. The independent oracle verifies the expected CBOR value of every claim,
one namespace, caller and digest-ID order, unique identities, the signed
`docType`, SHA-256 `valueDigests`, and each complete tag-24
`IssuerSignedItemBytes` commitment. Exact item and digest counts also confirm
that the modeled fixtures contain no decoys.

Scalar cases report item throughput. Sequential and batch cases report
credential throughput while holding payload class and per-credential item count
constant. The timed region contains production mdoc preparation only. It does
not include semantic fixture construction, request cloning, final assembly,
base64 transport encoding, or issuer signing.

For example, run the smallest complete class comparison in PowerShell with:

```powershell
$env:MARTY_MDOC_MATRIX = '1'
$env:MARTY_MDOC_MATRIX_CLASSES = 'small_primitive'
$env:MARTY_MDOC_MATRIX_ITEM_COUNTS = '1'
$env:MARTY_MDOC_MATRIX_BATCH_SIZES = '1'
cargo bench --locked -p marty-oid4vci --bench mdoc_issuance -- --noplot
```

The complete selection contains 20 scalar cases and 160 sequential/batch
cases. Use selectors to shard campaigns and retain Criterion's raw samples for
bidirectional revision comparisons. This matrix models the current SHA-256,
single-namespace, no-decoy issuance route; SHA-384/SHA-512 digests,
multi-namespace credentials, and decoy digest entries are unsupported by this
fixture model. It does not measure issuer signing, allocation totals, worker or
lane utilization, true per-invocation tail latency, or establish cross-platform
performance thresholds. Those require separately instrumented and qualified
campaigns.

## Opt-in internal mdoc stage evidence

The internal stage harness is a test-only child of the mdoc implementation. It
does not expose a library API, add production telemetry, or change production
dependencies or defaults. Its only entry point is an ignored unit test that
requires a release-profile build and the exact opt-in
`MARTY_MDOC_STAGE_EVIDENCE=1`.

The harness reuses the mdoc payload matrix's deterministic, non-personal class
and item-count model and these existing selectors:

- `MARTY_MDOC_MATRIX_CLASSES`: `small_primitive`, `medium_nested`,
  `large_portrait`, `mixed_size`
- `MARTY_MDOC_MATRIX_ITEM_COUNTS`: `1`, `8`, `32`, `128`, `512`

Each selector accepts a comma-separated subset, `all`, or may be omitted to
select every value. Whitespace around tokens is allowed. Unknown, empty,
non-Unicode, duplicate, noncanonical numeric, and `all`-combined selections
fail before fixture allocation. This scalar harness does not read the matrix's
batch-size selector.

Every selected fixture passes an untimed preflight before measurement. The
preflight independently checks converted CBOR values, claim uniqueness and
counts, deterministic salts, tag-24 item bytes, routing ordinals, serial
SHA-256 results, restored digest order, the encoded MSO digest map, and a full
production scalar replay. This guards the evidence boundary; it is not a
substitute for protocol-compliance tests.

Semantic names, values, identities, timestamps, and the ordinal salt tape are
fixed. Claim order retains the production `HashMap` iteration order and can
therefore differ between processes; preflight anchors identifiers and values
without assuming one global claim order.

Criterion records these exact IDs, with element throughput:

```text
mdoc_internal_stage_evidence/{class}/n={item_count}/validate_convert
mdoc_internal_stage_evidence/{class}/n={item_count}/salt_encode_plan
mdoc_internal_stage_evidence/{class}/n={item_count}/sha256_digest_serial
mdoc_internal_stage_evidence/{class}/n={item_count}/restore_digest_results
mdoc_internal_stage_evidence/{class}/n={item_count}/mso_and_tbs
```

The timed regions have deliberately narrow meanings:

- `validate_convert` includes document-type and namespace cloning, algorithm,
  certificate-chain extraction, validity, holder-key, and claim JSON-to-CBOR
  validation and conversion. These fixtures use an empty certificate chain and
  one valid ES256/P-256 holder-key profile.
- `salt_encode_plan` starts with validated claims prepared outside timing. It
  includes calls to the deterministic in-memory salt source, item construction,
  inner and tag-24 CBOR encoding, and digest-job planning. It does not measure a
  production entropy source or SHA-256.
- `sha256_digest_serial` executes the production `SerialDigestExecutor` over a
  prebuilt plan. It includes serial SHA-256 plus result allocation and routing
  metadata, so it is not a hash-compression-only microbenchmark.
- `restore_digest_results` starts with cloned plan and result inputs prepared
  outside timing. It includes length and identity validation, ordered lookup,
  item restoration, and output allocation; it performs no digest calculation.
- `mso_and_tbs` starts with validation, validity arithmetic, item planning,
  digest execution, and restoration already completed outside timing. It
  includes MSO construction and encoding, COSE headers, and Sig_structure TBS
  construction.

All five stages use the scalar production kernels. Fixture construction,
per-iteration input preparation or cloning, output destruction, issuer signing,
signed-credential assembly, and base64 transport encoding are outside timing.
Per-iteration batching bounds retained fixture memory and separates those
boundaries at the cost of additional timer overhead, which matters most for the
smallest cases.
Because each stage has an independent setup and ownership boundary, their
measurements are not additive end-to-end latency. The harness uses 10 samples,
a 250-ms warm-up, and a 500-ms requested measurement period; Criterion may
extend a case when needed. It does not measure allocation totals, worker or lane
utilization, production randomness, or true per-operation p95/p99 latency and
does not establish a speedup, threshold, or parallel policy. It exercises
successful, single-namespace, SHA-256 preparation only; invalid inputs,
alternate algorithms and curves, nonempty certificate chains, multiple
namespaces, and decoy digests require separate evidence.

Run the smallest release-profile evidence case in PowerShell with:

```powershell
$env:MARTY_MDOC_STAGE_EVIDENCE = '1'
$env:MARTY_MDOC_MATRIX_CLASSES = 'small_primitive'
$env:MARTY_MDOC_MATRIX_ITEM_COUNTS = '1'
cargo test --release --locked -p marty-oid4vci 'formats::mdoc::stage_evidence::collect_mdoc_stage_evidence' -- --ignored --exact --nocapture
```

## Opt-in aggregate mdoc allocation evidence

`mdoc_allocation_evidence` is a standalone, native release-profile evidence
binary. It is a successful no-op when `MARTY_MDOC_ALLOC_EVIDENCE` is absent.
When the variable is present it must equal exactly `1`; enabled debug/test
profile execution is rejected so its output cannot be mistaken for release
evidence. The existing `MARTY_MDOC_MATRIX` switch is irrelevant to this binary.

The binary reuses the mdoc payload matrix selector contract:

- `MARTY_MDOC_MATRIX_CLASSES`: `small_primitive`, `medium_nested`,
  `large_portrait`, `mixed_size`
- `MARTY_MDOC_MATRIX_ITEM_COUNTS`: `1`, `8`, `32`, `128`, `512`
- `MARTY_MDOC_MATRIX_BATCH_SIZES`: `1`, `8`, `32`, `256`

Omitted selectors choose all values. Each selector also accepts `all` or a
comma-separated subset. Unknown, empty, non-Unicode, duplicate, noncanonical
numeric, and `all`-combined selections fail before any semantic fixture is
allocated. The complete selection produces 20 scalar, 80 caller-sequential,
and 80 production-batch evidence rows. Shard it for routine campaigns: the
largest selected route can hold 256 credentials, and each `large_portrait`
credential has exactly one bounded 256-KiB value.

Before counters are enabled, every selected case is prepared, assembled, and
typed-CBOR decoded. The independent oracle checks caller and digest order,
unique credential and routing identities, one namespace, exact semantic claim
values, `docType`, SHA-256, every complete tag-24 item commitment, and the
absence of decoys. Measured outputs pass through the same oracle after the
counter snapshot, which both prevents optimizer elision and prevents an invalid
row from being emitted.

The measured boundaries match the payload matrix: public
`prepare_remote_mdoc`, a caller-side sequential loop that collects public
scalar results, and public `prepare_remote_mdoc_batch`. Semantic fixture and
request construction, correctness preflight, output assembly,
typed decode, output destruction, signing, base64 transport, and printing are
outside the counter window. Public preparation retains its production time,
random salts, reserved credential-ID validation (not UUID generation),
JSON-to-CBOR conversion, encoding, serial SHA-256, MSO construction, and
signing-input behavior.

The executable installs a benchmark-local wrapper around
`std::alloc::System`. During one synchronous boundary it reports successful
`alloc` plus `alloc_zeroed` calls and their gross requested `Layout::size()`
bytes. It reports successful `realloc` calls and requested new sizes separately.
These figures are not RSS, committed OS memory, net growth, retained/live
memory, peak memory, or deallocation totals. A realloc may occur in place, so
the two byte fields must not be added and described as actual memory use.

Counters are process-global. The runner creates no worker threads and the
current mdoc preparation routes are serial, but any concurrent in-process
allocation during or crossing the active counter window may be missed, recorded
late, spill across rows, or contaminate a row; its occurrence invalidates the
evidence. Results are specific to the recorded revision, target, profile, Rust
build, dependencies, and system allocator. Repeat campaigns on an otherwise
quiet host with the same toolchain; allocation evidence alone does not authorize
a routing threshold or parallel production path.

Each output line uses the `mdoc_requested_allocation_v1` schema. Metadata records
the Git revision when available, whether the worktree is clean, a sanitized
operator run label, package version, target architecture/OS/family, pointer
width, profile, available parallelism, allocator, counter scope, public
boundary, and fixture schema. Evidence rows contain only route, payload class,
`n`, `b` (`na` for scalar rows), credential count, and aggregate counters. They
contain no claims, credential identifiers, salts, digests, or per-item
scheduling identifiers.

For example, run the smallest release campaign in PowerShell with:

```powershell
$env:MARTY_MDOC_ALLOC_EVIDENCE = '1'
$env:MARTY_MDOC_ALLOC_EVIDENCE_RUN_LABEL = 'windows-x86_64-local'
$env:MARTY_MDOC_MATRIX_CLASSES = 'small_primitive'
$env:MARTY_MDOC_MATRIX_ITEM_COUNTS = '1'
$env:MARTY_MDOC_MATRIX_BATCH_SIZES = '1'
cargo bench --locked -p marty-oid4vci --bench mdoc_allocation_evidence
```

Unset `MARTY_MDOC_ALLOC_EVIDENCE` for the ordinary compile/no-op smoke gate:

```console
cargo test --locked -p marty-oid4vci --bench mdoc_allocation_evidence
```

Preserve the emitted metadata with campaign results and separately capture
`rustc -vV` plus a non-sensitive CPU/host description. Only treat a known
revision with `workspace_clean=true` as reproducible comparison evidence.

## Opt-in mdoc invocation-tail evidence

`mdoc_tail_evidence` is a standalone native evidence binary, not a Criterion
benchmark. It is disabled unless `MARTY_MDOC_TAIL_EVIDENCE=1` and rejects any
other value when the variable is set. Evidence collection also rejects debug
builds; use the optimized `cargo bench` command below. An unset gate exits
successfully without allocating fixtures so ordinary workspace commands remain
unchanged.

The binary reuses the payload matrix's strict selectors and exact dimensions:

- `MARTY_MDOC_MATRIX_CLASSES`: `small_primitive`, `medium_nested`,
  `large_portrait`, `mixed_size`
- `MARTY_MDOC_MATRIX_ITEM_COUNTS`: `1`, `8`, `32`, `128`, `512`
- `MARTY_MDOC_MATRIX_BATCH_SIZES`: `1`, `8`, `32`, `256`

Each selector accepts a comma-separated subset, `all`, or may be omitted for
all values. Whitespace around tokens is allowed. Unknown, empty, non-Unicode,
duplicate, noncanonical numeric, and `all`-combined selections fail before any
payload fixture is allocated. Selectors are ignored when the evidence gate is
unset.

`MARTY_MDOC_TAIL_SAMPLES` defaults to 200 and accepts canonical integers from
100 through 10,000. The minimum keeps nearest-rank p99 from being inferred from
fewer than 100 observations. `MARTY_MDOC_TAIL_WARMUP_INVOCATIONS` defaults to
10 and accepts canonical integers from 1 through 1,000. Both settings are
validated before fixture allocation. More samples improve the empirical order
statistics but do not by themselves make a tail estimate statistically robust.

For each selected case, the binary constructs one caller-ordered batch with
unique deterministic routing, issuer, and reserved credential identities. The
semantic claims are synthetic and non-personal. The `large_portrait` class has
exactly one 256-KiB value per credential rather than one per claim; the mixed
class has one 64-KiB value and bounded 1-KiB values. Production current-time and
salt sources remain active, and `HashMap` claim order can vary between
processes, so complete prepared bytes are not deterministic.

An untimed preflight runs the public batch-preparation and assembly APIs, then
performs a typed CBOR decode. Its independent oracle verifies caller order and
unique identities, exact claim values and counts, sequential digest IDs, one
namespace, SHA-256, document type, every complete tag-24 item commitment, and
the absence of modeled decoys. Assembly uses a fixed synthetic 64-byte
signature solely to validate structure; it does not prove signature validity.

Every recorded sample surrounds exactly one complete
`prepare_remote_mdoc_batch` invocation with `Instant`. The owned request clone
is prepared before the first clock read. The returned value is passed through
`black_box` before the second clock read to prevent optimizer elision, then is
dropped outside the timed interval. The sample vector is preallocated. The
reported batch-size dimension is the latency of one whole public batch call,
not a per-credential division. The optimizer barrier and clock-read overhead
remain part of the harness boundary, so timer resolution matters most for the
smallest cases.

Output uses reproducible case labels and integer nanoseconds:

```text
mdoc_invocation_tail/{class}/n={item_count}/b={batch_size} samples=... warmup=... method=nearest_rank unit=ns p50=... p95=... p99=...
```

Percentiles are nearest-rank order statistics over individually timed
invocations: rank `ceil(percentile * samples / 100)`. With 100 observations,
p99 is the 99th ordered observation; it is not a confidence bound or a claim
about an unobserved service-level tail. Repeat campaigns on an otherwise quiet
host and record the exact commit, `rustc -Vv`, target, CPU, power policy, and
environment.

Run the smallest campaign in PowerShell with:

```powershell
$env:MARTY_MDOC_TAIL_EVIDENCE = '1'
$env:MARTY_MDOC_MATRIX_CLASSES = 'small_primitive'
$env:MARTY_MDOC_MATRIX_ITEM_COUNTS = '1'
$env:MARTY_MDOC_MATRIX_BATCH_SIZES = '1'
$env:MARTY_MDOC_TAIL_SAMPLES = '100'
$env:MARTY_MDOC_TAIL_WARMUP_INVOCATIONS = '1'
cargo bench --locked -p marty-oid4vci --bench mdoc_tail_evidence
```

This evidence covers successful ES256/P-256, SHA-256, single-namespace remote
mdoc preparation with empty certificate chains and fixed reserved IDs. It does
not include UUID generation, issuer signing, signed-credential assembly,
base64 transport encoding, request cloning, fixture construction, preflight,
or output destruction in the timed interval. It is not a Criterion aggregate
average or an internal-stage measurement, and it makes no allocation, worker
or lane utilization, service-tail, cross-host comparability, production
threshold, or policy claim. Alternate algorithms and curves, invalid inputs,
nonempty certificate chains, multiple namespaces, and decoy digests require
separate evidence.


## ES256 credential signing batch benchmark

`es256_signing_batch` measures JWT-VC, proof-bound IETF SD-JWT, mdoc, and mixed
credential batches of 1, 8, 32, and 256 credentials. The original
`es256_signing_batch_mixed_jwt_mdoc` group and its benchmark IDs remain stable
for historical comparisons. A second stage group applies the same preparation,
raw ES256 signing, assembly, and end-to-end measurements to proof-bound SD-JWT.
Preparation and assembly deliberately run the same caller-side kernels for the
serial and concurrent stage labels; only signing uses the explicitly authorized
bounded worker path.

The `es256_signing_batch_total_by_composition` group measures complete serial
and concurrent signing-batch routes for JWT-VC, proof-bound SD-JWT, mdoc, and a
three-format mix. Concurrent cases request worker limits `p={1,2,4,8}`, filtered
to limits supported by the host's available parallelism. Batch inputs retain
unique caller-ordered route IDs. An untimed preflight covers every composition
and batch size through the production serial and concurrent APIs, verifies all
ES256 signatures and format-specific ordinals, and checks that the SD-JWT
confirmation key is the expected public-only holder key.

Run a compile/smoke check with:

```console
cargo test --locked -p marty-oid4vci --bench es256_signing_batch
```

Collect measurements with:

```console
cargo bench --locked -p marty-oid4vci --bench es256_signing_batch -- --noplot
```

Run campaigns on an otherwise quiet machine and record the exact commit, target,
CPU, available parallelism, Rust toolchain, and composition. Preserve Criterion's
raw samples so median and 95% confidence intervals can be reported alongside
externally derived p95/p99 latency and credential throughput. Allocation and
worker-utilization evidence require separate instrumentation; this benchmark
does not claim to measure either.

The concurrent benchmark is native-only. WASM retains the serial production
fallback and must be documented separately rather than inferred from native
results. These measurements are evidence, not a speedup guarantee, automatic
production threshold, or permission to change the default serial policy. Real
results depend heavily on signer latency, backend quotas, worker authorization,
batch composition, and host scheduling.

### Opt-in ES256 payload matrix

The payload matrix is disabled unless `MARTY_ES256_MATRIX=1`. The default smoke
command above preserves its historical workload when the matrix variables are
unset. Enabling the matrix adds
the `es256_signing_batch_total_payload_matrix` group without changing the
historical groups, benchmark IDs, production defaults, or
serial policy. Its complete Criterion IDs have the following shape:

```text
es256_signing_batch_total_payload_matrix/{format}/{class}/n={item_count}/serial/b={batch_size}
es256_signing_batch_total_payload_matrix/{format}/{class}/n={item_count}/concurrent/p={worker_limit}/b={batch_size}
```

The matrix dimensions and exact selector values are:

- `MARTY_ES256_MATRIX_FORMATS`: `jwt_vc`,
  `proof_bound_ietf_sd_jwt`, `proof_bound_w3c_sd_jwt`, `mdoc`
- `MARTY_ES256_MATRIX_CLASSES`: `small_primitive`, `medium_nested`,
  `large_portrait`, `mixed_size`
- `MARTY_ES256_MATRIX_ITEM_COUNTS`: `1`, `8`, `32`, `128`, `512`
- `MARTY_ES256_MATRIX_BATCH_SIZES`: `1`, `8`, `32`, `256`

Each selector accepts a comma-separated subset, `all`, or may be omitted for
all values. Whitespace around comma-separated tokens is allowed. Unknown,
empty, non-Unicode, duplicate, noncanonical numeric, and `all`-combined values
fail closed before any historical preflight or benchmark group runs. Fixture
names, semantic values, and bounded shapes are deterministic and contain no
personal data. Standard `HashMap` iteration and production UUID, time, and salt
sources remain unfixed, so complete credential bytes are not deterministic. The
large class has one bounded 256-KiB opaque value rather than `n` such values, and
the mixed class is also bounded. Before timing, selected formats and classes are
checked at `n=1` and `n=512` with `b=1`, independent of the timed item-count and
batch-size filters.
The preflight verifies exact ES256 declarations, signatures, format contents,
and fixture values. Both SD-JWT formats must have their exact expected key sets,
all selected claims must be hidden, disclosures must be hash-linked to the
signed payload, and the holder key must remain public-only. The mdoc oracle also
checks its single namespace and every Tag24 item digest against the signed MSO.

For example, run a small native campaign in PowerShell with:

```powershell
$env:MARTY_ES256_MATRIX = '1'
$env:MARTY_ES256_MATRIX_FORMATS = 'jwt_vc,proof_bound_ietf_sd_jwt'
$env:MARTY_ES256_MATRIX_CLASSES = 'small_primitive,mixed_size'
$env:MARTY_ES256_MATRIX_ITEM_COUNTS = '1,512'
$env:MARTY_ES256_MATRIX_BATCH_SIZES = '1,8'
cargo bench --locked -p marty-oid4vci --bench es256_signing_batch -- --noplot
```

The complete cross-product is 4 formats x 4 classes x 5 item counts x 4
batch sizes x (serial plus as many as four host-supported worker limits): up
to 1,600 timed cases. With this benchmark's minimum warm-up and measurement
periods it can take well over 80 minutes, before compile and preflight time, so
use the selectors to shard repeatable matrix selections and runtime campaign
configurations. Criterion captures
aggregate timing samples, estimates, confidence intervals, and throughput. It
does not directly capture allocation bytes, worker utilization, or true
per-operation p95/p99; retain its raw samples and gather those measurements in
separately instrumented campaigns.

For each matrix case, fixed signer and semantic claim construction is untimed;
production serialization and issuance randomness remain exercised. Only scope
construction and the production serial or concurrent batch call are
timed. `BatchSize::PerIteration` excludes setup and output cleanup from the
sample while preventing large fixtures from accumulating across iterations.

The native-only matrix compares the serial route with the bounded concurrent
route. WASM continues to use
the production serial fallback through `Es256SignerScope`. Matrix evidence is
diagnostic and makes no production policy, concurrency-bound, or threshold
change.
