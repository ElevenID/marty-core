#!/usr/bin/env bash
set -euo pipefail

# This process owns a fresh, disposable OpenBao. The Rust test checks its
# marker before creating any key and receives only a scoped sign token.
image='quay.io/openbao/openbao@sha256:6150c4a6b62067db6141c8da7a6a6b5763f4f47c315343d0c848b40fecdfd452'
name="marty-core-issuer-kms-${GITHUB_RUN_ID:-local}-$$"
token='core-issuer-test-only'
nonce="$(python3 -c 'import secrets; print(secrets.token_hex(24))')"

docker run --rm -d --name "$name" \
  -e "BAO_DEV_ROOT_TOKEN_ID=$token" \
  -p 127.0.0.1::8200 \
  "$image" server -dev '-dev-listen-address=0.0.0.0:8200' >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT

binding="$(docker port "$name" 8200/tcp)"
base="http://127.0.0.1:${binding##*:}"
for attempt in {1..30}; do
  if curl --silent --fail "$base/v1/sys/health" >/dev/null; then
    break
  fi
  if (( attempt == 30 )); then
    docker logs "$name" >&2
    exit 1
  fi
  sleep 1
done

curl --silent --show-error --fail \
  --header "X-Vault-Token: $token" \
  --header 'Content-Type: application/json' \
  --request POST \
  --data "{\"data\":{\"nonce\":\"$nonce\"}}" \
  "$base/v1/secret/data/marty-test-disposable-guard" >/dev/null
curl --silent --show-error --fail \
  --header "X-Vault-Token: $token" \
  --header 'Content-Type: application/json' \
  --request POST \
  --data '{"type":"transit"}' \
  "$base/v1/sys/mounts/transit" >/dev/null

export MARTY_TEST_OPENBAO_URL="$base"
export MARTY_TEST_OPENBAO_TOKEN="$token"
export MARTY_TEST_OPENBAO_DISPOSABLE_NONCE="$nonce"
features='kms-only,issuer,verifier,wallet,jwt_vc_json,sd_jwt,mso_mdoc,lti'
cargo="${MARTY_TEST_CARGO:-cargo}"
if [[ "$cargo" == *.exe ]]; then
  # WSL does not forward newly created environment variables to Windows
  # executables unless they are named in WSLENV. This is local probe wiring;
  # Linux CI continues to use its native cargo and inherited environment.
  export WSLENV="${WSLENV:+$WSLENV:}MARTY_TEST_OPENBAO_URL/w:MARTY_TEST_OPENBAO_TOKEN/w:MARTY_TEST_OPENBAO_DISPOSABLE_NONCE/w"
fi
if [[ "${MARTY_TEST_ZK_MDOC:-0}" == '1' ]]; then
  features+=',zk_mdoc'
fi
run_bench_smoke() {
  "$cargo" test --locked -p marty-oid4vci --test benchmark_support \
    --no-default-features --features "$features" -- --ignored
  for bench in mdoc_issuance sd_jwt_issuance mdoc_allocation_evidence mdoc_tail_evidence es256_signing_batch; do
    "$cargo" test --locked -p marty-oid4vci --bench "$bench" \
      --no-default-features --features "$features" -- --test
  done
  if [[ "${MARTY_TEST_BENCH_MATRIX:-0}" == '1' ]]; then
    MARTY_ES256_MATRIX=1 MARTY_ES256_MATRIX_FORMATS=all \
      MARTY_ES256_MATRIX_CLASSES=all MARTY_ES256_MATRIX_ITEM_COUNTS=1,512 \
      MARTY_ES256_MATRIX_BATCH_SIZES=1 \
      "$cargo" test --locked -p marty-oid4vci --bench es256_signing_batch \
      --no-default-features --features "$features" -- --test
    MARTY_MDOC_MATRIX=1 MARTY_MDOC_MATRIX_CLASSES=all \
      MARTY_MDOC_MATRIX_ITEM_COUNTS=1,512 MARTY_MDOC_MATRIX_BATCH_SIZES=1 \
      "$cargo" test --locked -p marty-oid4vci --bench mdoc_issuance \
      --no-default-features --features "$features" -- --test
    MARTY_MDOC_MATRIX=1 MARTY_MDOC_MATRIX_CLASSES=small_primitive \
      MARTY_MDOC_MATRIX_ITEM_COUNTS=1 MARTY_MDOC_MATRIX_BATCH_SIZES=256 \
      "$cargo" test --locked -p marty-oid4vci --bench mdoc_issuance \
      --no-default-features --features "$features" -- --test
  fi
}
if [[ "${MARTY_TEST_BENCH_SMOKE:-0}" == '1' ]]; then
  run_bench_smoke
  exit 0
fi
if [[ -n "${MARTY_TEST_BENCH_RUN:-}" ]]; then
  case "$MARTY_TEST_BENCH_RUN" in
    mdoc_issuance|sd_jwt_issuance|mdoc_allocation_evidence|mdoc_tail_evidence|es256_signing_batch) ;;
    *) echo "unsupported KMS benchmark: $MARTY_TEST_BENCH_RUN" >&2; exit 2 ;;
  esac
  "$cargo" bench --locked -p marty-oid4vci --bench "$MARTY_TEST_BENCH_RUN" \
    --no-default-features --features "$features"
  exit 0
fi
"$cargo" test --locked -p marty-oid4vci --test benchmark_support \
  --no-default-features --features "$features" -- --ignored
"$cargo" test --locked -p marty-oid4vci --lib \
  --no-default-features --features "$features" \
  signing_batch::tests \
  -- --ignored
"$cargo" test --locked -p marty-oid4vci --lib \
  --no-default-features --features "$features" \
  formats::vds_nc::tests \
  -- --ignored
"$cargo" test --locked -p marty-verification --lib \
  verification::vds_nc::tests -- --ignored
"$cargo" test --locked -p marty-verification --lib \
  oid4vp::tests -- --ignored
"$cargo" test --locked -p marty-verification --lib \
  trust_sync::tests -- --ignored
"$cargo" test --locked -p marty-verification --test mdl_conformance -- --ignored
"$cargo" test --locked -p marty-verification --test chain_validation_tests -- --ignored
"$cargo" test --locked -p marty-oid4vci --lib \
  --no-default-features --features "$features" \
  formats::mdoc::tests \
  -- --ignored
"$cargo" test --locked -p marty-oid4vci --lib \
  --no-default-features --features "$features" \
  jose::tests \
  -- --ignored
"$cargo" test --locked -p marty-oid4vci --lib \
  --no-default-features --features "$features" \
  oidc::tests \
  -- --ignored
"$cargo" test --locked -p marty-oid4vci --lib \
  --no-default-features --features "$features" \
  siop::tests \
  -- --ignored
"$cargo" test --locked -p marty-oid4vci --lib \
  --no-default-features --features "$features" \
  wallet::tests \
  -- --ignored
"$cargo" test --locked -p marty-oid4vci --lib \
  --no-default-features --features "$features" \
  signer::remote_signature_tests \
  -- --ignored
"$cargo" test --locked -p marty-oid4vci --lib \
  --no-default-features --features "$features" \
  proof::tests \
  -- --ignored
"$cargo" test --locked -p marty-oid4vci --lib \
  --no-default-features --features "$features" \
  lti::tests \
  -- --ignored
"$cargo" test --locked -p marty-oid4vci --test remote_issuer_live_kms \
  --no-default-features --features "$features" \
  -- --ignored
"$cargo" test --locked -p marty-oid4vci --test oid4vp_conformance \
  --no-default-features --features "$features" \
  -- --ignored --skip siop_v2
"$cargo" test --locked -p marty-bindings --lib \
  vds_nc_profile_binding_signs_and_verifies_in_rust -- --ignored
"$cargo" test --locked -p marty-bindings --lib \
  remote_mdoc_batch_handle_uses_existing_single_use_sign_and_assemble_route -- --ignored
"$cargo" test --locked -p marty-bindings --lib \
  remote_credential::tests -- --ignored
"$cargo" test --locked -p marty-emrtd-issuance --test remote_sod -- --ignored
if [[ "${MARTY_TEST_BENCH_AFTER_LIVE:-0}" == '1' ]]; then
  run_bench_smoke
fi
