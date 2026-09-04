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
