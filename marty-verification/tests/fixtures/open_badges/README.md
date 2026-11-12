# Open Badges interoperability and retirement fixtures

`ob3_verify_request.json` is a deterministic signed OB3 verification request.
The OB3 interoperability test accepts `OPEN_BADGES_OB3_VERIFY_REQUEST` as an
optional path override.

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
