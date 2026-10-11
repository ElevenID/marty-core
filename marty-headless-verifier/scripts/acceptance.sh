#!/usr/bin/env bash
set -euo pipefail

bundle="${1:?pass the extracted bundle directory}"
test -x "$bundle/bin/marty-headless-verify"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
digest="$(sha256sum "$bundle/samples/demo-trust-profile.json" | cut -d ' ' -f 1)"
test "$digest" = 8a0fd4579fbf239f54598ea06b986e1bd70bae1549b7e3942ac2c4a05b95980e

"$bundle/bin/marty-headless-verify" verify \
  --credential "$bundle/samples/ob3-valid.json" \
  --trust-profile "$bundle/samples/demo-trust-profile.json" \
  --trust-sha256 "$digest" > "$work/accepted.json"
jq -e '.accepted == true' "$work/accepted.json" >/dev/null

denied() {
  local credential="$1" profile="$2" pin="$3" output="$4"
  if "$bundle/bin/marty-headless-verify" verify \
    --credential "$credential" --trust-profile "$profile" \
    --trust-sha256 "$pin" > "$output"; then
    echo "Unexpected acceptance: $credential" >&2
    exit 1
  fi
  jq -e '.accepted == false' "$output" >/dev/null
}

jq '.credentialSubject.achievement.name = "Tampered"' \
  "$bundle/samples/ob3-valid.json" > "$work/tampered.json"
denied "$work/tampered.json" "$bundle/samples/demo-trust-profile.json" \
  "$digest" "$work/tampered-result.json"

jq '.trusted_issuer = "did:example:other"' \
  "$bundle/samples/demo-trust-profile.json" > "$work/wrong-trust.json"
wrong_digest="$(sha256sum "$work/wrong-trust.json" | cut -d ' ' -f 1)"
denied "$bundle/samples/ob3-valid.json" "$work/wrong-trust.json" \
  "$wrong_digest" "$work/wrong-trust-result.json"

jq '.validUntil = "2020-01-01T00:00:00Z"' \
  "$bundle/samples/ob3-valid.json" > "$work/expired.json"
denied "$work/expired.json" "$bundle/samples/demo-trust-profile.json" \
  "$digest" "$work/expired-result.json"
jq -e '.reasons | index("credential has expired") != null' \
  "$work/expired-result.json" >/dev/null

jq '.credentialStatus = {"type":"BitstringStatusListEntry","statusListCredential":"https://example.test/status","statusListIndex":"0","statusPurpose":"revocation"}' \
  "$bundle/samples/ob3-valid.json" > "$work/status.json"
denied "$work/status.json" "$bundle/samples/demo-trust-profile.json" \
  "$digest" "$work/status-result.json"
jq -e '.verification.error_codes | index("E710") != null' \
  "$work/status-result.json" >/dev/null

if "$bundle/bin/marty-headless-verify" verify \
  --credential "$bundle/samples/ob3-valid.json" \
  --trust-profile "$bundle/samples/demo-trust-profile.json" \
  --trust-sha256 "$(printf '0%.0s' {1..64})" > "$work/wrong-pin.json" 2> "$work/wrong-pin.err"; then
  echo 'Changed trust profile pin was accepted' >&2
  exit 1
fi
test ! -s "$work/wrong-pin.json"
grep -Fq 'does not match the pinned SHA-256' "$work/wrong-pin.err"
echo 'Headless verifier extracted-bundle acceptance passed'
