# mdoc issuance preparation benchmark

`mdoc_issuance` measures Marty's public remote-signing preparation route with
1, 8, 32, 128, and 512 issued elements. Each element has a deterministic
256-byte value. A preflight assembles and decodes every fixture, then checks
the reserved credential ID, namespace and item counts, sequential digest IDs,
SHA-256 algorithm, and every tag-24 `IssuerSignedItemBytes` commitment before
timing begins.

The timed region includes request validation, salts, JSON-to-CBOR conversion,
item and tag-24 encoding, serial SHA-256 commitments, MSO construction, holder
binding, and COSE signing-input preparation. Request cloning, Python/FFI work,
signing or KMS latency, final assembly, and base64 transport encoding are
outside the timed region.

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
estimates, 95% confidence intervals, and element throughput. These results are
an issuance-preparation baseline, not an isolated SHA benchmark, and do not by
themselves authorize a parallel route or production threshold.
