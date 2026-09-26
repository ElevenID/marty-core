# Keyless eMRTD SOD assembly

`marty-emrtd-issuance` owns the reusable ICAO EF.SOD/CMS encoding boundary. It
accepts raw data groups and a public Document Signer Certificate, prepares the
DER CMS signed attributes, and verifies an externally produced signature before
assembling EF.SOD. Its production API has no private-key input or local signer.

The service must resolve an active organization-scoped `ICAO_EMRTD`
`x509_doc_signer` profile, validate its DSC certificate and chain for that
issuer, send `PreparedSod::signing_input()` to the profile's authorized KMS
signing operation, and pass the provider-native signature to `assemble()`.
ECDSA signatures are ASN.1 DER, RSA signatures are PKCS#1 v1.5 bytes, and
Ed25519 signatures are the 64-byte PureEdDSA value. Data groups 1 through 20,
including the original builder's 17-20 extensions, remain supported. The profile
algorithms are ES256, ES384, RS256, and EdDSA (Ed25519); mismatches fail closed against
the DSC public key. The LDS data-group hash remains SHA-256 for all four.

This crate verifies signature/key correspondence, not issuer authorization,
certificate-chain trust, revocation, service authentication, or bureau delivery.
Those checks belong in the consuming service and must pass before beta cutover.
Synthetic private keys appear only in tests.
