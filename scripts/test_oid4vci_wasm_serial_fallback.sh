#!/usr/bin/env bash
set -euo pipefail

readonly oid4vci_features="issuer,jwt_vc_json,sd_jwt,mso_mdoc"

# All eight behavioral oracles below execute natively and define the serial
# bytes, error, and ordering contract. The later browser-WASM leg is compile-only
# positive/negative API capability evidence; it is not browser runtime proof.
#
# Even `cargo test --no-run --target wasm32-unknown-unknown` is unavailable:
# marty-oid4vci's unconditional Tokio dev-dependency inherits the workspace
# `features = ["full"]`, which pulls mio, and mio rejects wasm32-unknown-unknown
# as unsupported. Keep the full oracle names so renamed or removed tests fail
# this gate instead of silently matching nothing.
readonly -a serial_oracles=(
  "formats::mdoc::tests::deterministic_nested_claims_round_trip_with_exact_commitments"
  "formats::mdoc::tests::serial_mdoc_digest_plan_matches_the_inline_digest_oracle"
  "formats::mdoc::tests::mdoc_batch_planner_validates_in_caller_order_and_stops_before_sources"
  "formats::sd_jwt::tests::deterministic_sources_freeze_preparation_bytes_and_consumption_order"
  "formats::sd_jwt::tests::w3c_fixed_id_and_disclosure_freeze_bytes_without_consuming_uuid"
  "formats::sd_jwt::tests::staged_sd_jwt_preserves_error_precedence_and_source_consumption"
  "signing_batch::tests::jwt_sd_jwt_and_mdoc_sign_complete_payloads_and_preserve_raw_p1363_bytes"
  "signing_batch::tests::backend_failure_is_redacted_and_returns_no_partial_outputs"
)

readonly -a oracle_args=(
  cargo test --locked -p marty-oid4vci --lib
  --no-default-features --features "$oid4vci_features"
)
oracle_inventory="$("${oracle_args[@]}" -- --list)"
readonly oracle_inventory

for serial_oracle in "${serial_oracles[@]}"; do
  if ! grep -Fqx "$serial_oracle: test" <<<"$oracle_inventory"; then
    printf 'required serial oracle is missing: %s\n' "$serial_oracle" >&2
    exit 1
  fi
  "${oracle_args[@]}" "$serial_oracle" -- --exact
done

readonly cdla_target_dir="target/cdla-wasm-serial-fallback"
readonly probe_stderr="$cdla_target_dir/native-worker-probe.stderr"

readonly -a probe_args=(
  --locked --color never
  --target wasm32-unknown-unknown
  -p marty-oid4vci-wasm-serial-probe
)

# Compile-only positive control: a browser-WASM consumer can compile the public
# serial scope and exact issuer/format feature set without the package's
# native-only test dependencies. This does not execute the code in a WASM runtime.
CARGO_TARGET_DIR="$cdla_target_dir" cargo build "${probe_args[@]}"

# Compile-only negative control: the native capability, concurrent scope, and
# worker ceiling must not exist in the browser-WASM public surface.
if CARGO_TARGET_DIR="$cdla_target_dir" cargo rustc "${probe_args[@]}" \
  -- --cfg cdla_native_worker_probe 2>"$probe_stderr"
then
  printf 'native OID4VCI worker routes unexpectedly compiled for browser WASM\n' >&2
  exit 1
fi

if ! grep -Fq 'error[E0432]: unresolved imports' "$probe_stderr"; then
  cat "$probe_stderr" >&2
  printf 'native worker probe failed for an unexpected reason\n' >&2
  exit 1
fi

for native_route in \
  BoundedConcurrentCredentialSigner \
  ConcurrentEs256SignerScope \
  MAX_CONCURRENT_SIGNING_WORKERS
do
  if ! grep -Fq "no \`$native_route\` in \`signing_batch\`" "$probe_stderr"; then
    cat "$probe_stderr" >&2
    printf 'browser-WASM build did not prove %s unavailable\n' "$native_route" >&2
    exit 1
  fi
done
