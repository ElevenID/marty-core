# marty-verification-py

Python bindings for the `marty-verification` Rust library, providing cryptographic verification and Open Badges support.

Python extensions are built from Rust by Maturin using this crate's declared
KMS-only feature profile, or installed from a platform release wheel. Compiled
`.so`/`.pyd` files must not be committed into the Python source package. A checkout
without a built extension cannot perform native verification; it must not load a
stale prebuilt artifact or substitute Python cryptography. Release wheel preflight
checks the built wheel through the public import and clean-consumer boundaries.

## Features

- **Open Badges 3**: Current/default verification profile
- **Open Badges 2**: Temporary migration-only verification support
- **mDoc/mDL Verification**: Verify mobile driver's licenses (ISO 18013-5)
- **eMRTD Verification**: Verify electronic machine-readable travel documents
- **MRZ Parsing**: Parse and validate machine-readable zone data
- **Certificate Operations**: Parse and verify X.509 certificate chains
- **Public Cryptography**: Ed25519, ECDSA, and RSA verification; hashing;
  public-key/certificate conversion to bounded public JWKs

The verifier has no selectable local-key, certificate-builder, or
authority-issuance feature. CSCA/DSC key generation, certificate/SOD
construction, and passport personalization belong behind remote KMS-backed
service APIs; ordinary `csca` enables eMRTD verification only.

## Installation

```bash
pip install marty-verification-py
```

## Usage

### Open Badges

Open Badges 3 is the current/default profile. Open Badges 2 remains available
only for a short migration window: review on 2026-09-01 and target removal on
2026-10-01, tracked in
[marty-core#96](https://github.com/ElevenID/marty-core/issues/96). Do not build
new integrations against the OB2 entry points.

Current integrations should use the Open Badges verification entry points.
Issuance must use a service-level prepare/KMS/assemble flow rather than passing
private JWK material to this verifier.

```python
import json
from marty_verification_py import open_badge_ob3_verify_at

request = {"credential": signed_credential, "document_store": issuer_documents}
result = json.loads(open_badge_ob3_verify_at(json.dumps(request), "2026-01-01T00:00:00Z"))
```

The explicit-time entry point evaluates OB3 credential validity at the supplied
RFC 3339 instant. The caller must obtain a trustworthy clock and authenticate
issuer documents; supplying either value does not make it trusted. The existing
`open_badge_ob3_verify(request_json)` retains its system-clock behavior. OB2
expiry semantics are not part of this entry point.

### MRZ Parsing

```python
from marty_verification_py import parse_mrz

mrz_lines = [
    "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<<",
    "L898902C36UTO7408122F1204159ZE184226B<<<<<10"
]
mrz_data = parse_mrz(mrz_lines)
print(f"Name: {mrz_data.given_names} {mrz_data.surname}")
```

## Building from Source

```bash
cd marty-core/marty-verification
maturin build --release --features python
pip install target/wheels/marty_verification_py-*.whl
```

## License

MIT OR Apache-2.0
