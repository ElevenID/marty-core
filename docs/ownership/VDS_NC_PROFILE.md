# Canonical VDS-NC profile ownership

`marty-oid4vci::formats::vds_nc_profile` is the sole owner of Marty VDS-NC
document schemas, normalization, envelope parsing, field comparison, temporal
policy, and barcode-format selection. `marty-verification` owns signature and
overall verification result composition while consuming that profile module.

Bindings and service adapters may select persisted keys, invoke external KMS
signing, map DTOs, and render barcodes. They must not reconstruct profile
headers, canonical JSON, signed bytes, schema rules, field comparisons, date
decisions, or barcode capacity tables.

The canonical envelope is bounded and has exactly three segments:

`DC03<COUNTRY>~<canonical-profile-json>~<signature-base64>`

The signed JSON includes `_vds` metadata identifying profile version, document
type, issuer, key, optional certificate reference, and algorithm. ES256, ES384,
Ed25519, and RSA-PSS SHA-256/384/512 profiles are supported. Input with an
unknown field, malformed date, non-canonical JSON, metadata/header mismatch,
unsupported algorithm, or invalid signature fails closed.

Shared profile vectors live in `tests/vectors/vds_nc_profile.json`. A caller
cutover is complete only after it consumes the native APIs and deletes its local
profile, canonicalization, verification, temporal, and barcode-policy code.
