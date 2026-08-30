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

`es256_signing_batch` measures mixed JWT-VC/mdoc batches of 1, 8, 32, and 256
credentials. It reports canonical preparation, raw ES256 signing, canonical
assembly, and end-to-end total separately. Each phase has serial and concurrent
labels; preparation and assembly deliberately run the same caller-side kernels
for both labels, while only signing uses the explicitly authorized bounded
worker path.

Run a compile/smoke check with:

```console
cargo test --locked -p marty-oid4vci --bench es256_signing_batch
```

Collect measurements with:

```console
cargo bench --locked -p marty-oid4vci --bench es256_signing_batch -- --noplot
```

The benchmark is evidence, not a speedup guarantee or an automatic production
threshold. Real results depend heavily on signer latency, backend quotas,
worker authorization, batch composition, and host scheduling.
