# Open Badges interoperability and retirement fixtures

`ob3_verify_request.json` reuses an existing signature-valid public vector and
its public verification method as an interoperability request. It exercises the
bounded proof, issuer, and criteria checks; it omits OB3-required `validFrom`
and is not evidence of full JSON Schema or Open Badges conformance.
The OB3 interoperability test accepts `OPEN_BADGES_OB3_VERIFY_REQUEST` as an
optional path override.

`ob3_missing_criteria_verify_request.json` preserves the previous interoperability
request byte-for-byte. Its proof is valid but its achievement omits required
`criteria`; the Data Integrity verifier must reject it with only the profile
error, not a proof error. The historical Ed25519 2018/2020 method vectors are
likewise preserved and require successful proof processing before this same
profile rejection.

`ob2_verify_request.json` is retained only as negative and migration evidence.
Its old signature and assertion body must remain unchanged. It is no longer an
accepted verification request and has no environment override or OB2 verifier.
The retirement tests require raw, wrapped, mixed-context, and JWT-contained legacy
assertions to remain unsupported. Migration requires a newly issued OB3 credential.

`ob3_jwt_verify_request.json` retains the public-only signed ES256 OB3 JWT vector
also used by the presentation-policy issuer-key regression suite. Its original
signed credential omits required `achievement.criteria`, so it is retained as
negative profile evidence: generic signature/VCDM verification succeeds, while
Open Badges verification must reject the profile and withhold its claims. Do not
repair the signed payload or treat this vector as a valid OB3 credential.

Historical signed OB3 JWTs without embedded `vc.id` or `achievement.criteria`
now fail the dedicated OB3 profile verifier, even when generic signature/VCDM
verification succeeds. Obtain a newly issued complete credential; do not add
properties to the signed payload or silently reinterpret `jti` as `vc.id`.
