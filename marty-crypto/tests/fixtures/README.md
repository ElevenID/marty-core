# Public verification fixtures

`pss_algorithm_identifier_public.json` contains synthetic RSA public keys and
signed messages for SHA-256, SHA-384, and SHA-512 PSS identifiers with
non-default salt lengths. The algorithm-identifier verifier uses these public
artifacts to check the declared hash, MGF1 and salt parameters without
generating or importing a private key in the test.

These vectors establish public verification behavior only. They are not
remote-signing or production KMS custody evidence.

`certificate_parser_public.json` contains two synthetic public X.509 DER
certificates. One carries a CRL distribution URI and the other carries a PKD
DNS name. Certificate parsing tests use only those public bytes and no longer
generate local certificate keys.

`pss_certificate_public.json` contains a synthetic issuer certificate and a
subject certificate signed with parameterized RSA-PSS. The signature test
retains successful verification, algorithm-mismatch rejection, and tampered
signature rejection using public DER only. The test does not re-sign the
certificate or load an issuer private key.

`crl_parser_public.json` contains a synthetic signed CRL with two revoked
serials and CRL number 1. Its parser and membership tests consume public DER
only; they do not claim current freshness or signature validation.

`crl_authenticated_public.json` contains a synthetic public CA certificate,
leaf certificate and signed CRL plus the fixed validation instant when the
CRL was issued. Authenticated tests check revocation, issuer binding, signature
tampering, future issue time and expiration at that fixed instant. The
production validator still reads the system clock. No private key is retained
in the fixture or consumed by these CRL tests.

`ocsp_authenticated_public.json` contains a synthetic public CA certificate,
two leaf certificates, and issuer-signed good and revoked OCSP responses. The
fixed validation instant keeps signature, certificate binding, responder
authorization, revocation, tamper, future-time and expiration checks stable.
Production OCSP validation still reads the system clock; the fixture retains
no signer or private key.

`rsa_verification_public.json` contains two synthetic RSA public SPKI keys and
public signatures for RS256/384/512 and PS256/384/512. The verifier checks all
six positive algorithms, message/key/tamper and cross-scheme rejection, and
two distinct valid PSS signatures for one message. No private key or signer is
available to the Rust tests.

`iso9796_scheme1_public.json` contains a synthetic RSA public SPKI key, a
message and its ISO 9796-2 Scheme 1 signature. Recovery, successful
verification, wrong-message and tamper tests consume only those public bytes.
The retired test-only RSA signer was used once to capture the vector; its
private key is not retained.

`bbs_disclosure_public.json` contains synthetic BBS+ public keys and signed
multi-message inputs for SHA-256 and SHAKE-256 ciphersuites. Tests verify the
signatures, reject altered inputs, create holder selective-disclosure proofs,
and reject altered disclosures and presentation headers. No issuer secret key
or signing operation remains in the test suite.
