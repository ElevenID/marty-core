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
