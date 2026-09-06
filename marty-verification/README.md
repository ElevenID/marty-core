# marty-verification-py

Python bindings for the `marty-verification` Rust library, providing cryptographic verification and Open Badges support.

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
from marty_verification_py import open_badge_ob3_verify

result = open_badge_ob3_verify(signed_credential, trusted_issuer_document)
```

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
