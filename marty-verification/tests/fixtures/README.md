# VCDM interoperability fixtures

`w3c_vcdm_v2_official_suite_presentation.json` was generated with the pinned
W3C VC Data Model 2.0 test suite at commit
`1db599924e6601555933550e0e65925a6abbd0a8`, using its published
`tests/data-generator.js` EdDSA-RDFC-2022 path and a fixed challenge/domain for
repeatable verification. The upstream suite is licensed under
`LicenseRef-w3c-3-clause-bsd-license-2008 OR LicenseRef-w3c-test-suite-license-2023`.

## Public-key to JWK vectors

`public_key_jwk_vectors.json` is a language-neutral behavioral contract for
the signing-key/KMS migration. It contains SubjectPublicKeyInfo PEM and DER
representations for RSA-2048, P-256, P-384, Ed25519, and Ed448 public keys, the exact
RFC 7517 public JWK expected for each key, one X.509 certificate extraction
vector, and malformed DER cases. The fixture contains public material only and
can be consumed by Rust services and compatibility-wrapper tests alike.
