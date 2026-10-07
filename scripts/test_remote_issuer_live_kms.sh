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
cargo test --locked -p marty-oid4vci --test remote_issuer_live_kms \
  --no-default-features --features kms-only,issuer,jwt_vc_json,sd_jwt,mso_mdoc \
  -- --ignored
