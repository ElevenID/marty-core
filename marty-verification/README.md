# marty-verification-py

Python bindings for the `marty-verification` Rust library, providing cryptographic verification and Open Badges support.

## Features

- **Open Badges 3**: Current/default issuance and verification profile
- **mDoc/mDL Verification**: Verify mobile driver's licenses (ISO 18013-5)
- **eMRTD Verification**: Verify electronic machine-readable travel documents
- **MRZ Parsing**: Parse and validate machine-readable zone data
- **Certificate Operations**: Parse and verify X.509 certificate chains
- **Cryptographic Primitives**: Ed25519, P-256, RSA, hashing, JWK/JWS/JWE

The released verifier wheel intentionally excludes CSCA/DSC key generation,
certificate/SOD construction, and passport personalization. Rust development
and authority tooling can select the explicit `authority-issuance` feature to
compile those APIs; ordinary `csca` enables eMRTD verification only.

## Installation

```bash
pip install marty-verification-py
```

## Usage

### Open Badges

Open Badges 3 is the supported profile. Open Badges 2 issuance and verification
APIs have been removed, including the Python `open_badge_ob2_issue` and
`open_badge_ob2_verify` entry points. Legacy assertions are rejected even when
wrapped or labelled as OB3. Ask the original issuer for a newly issued OB3
credential; editing the context, type, or version does not migrate a signed badge.

This maintenance branch retains `open_badge_ob3_issue` and
`open_badge_ob3_verify` for OB3 issuance and verification.

```python
import json
from marty_verification_py import open_badge_ob3_verify

request = {"credential": signed_credential, "document_store": issuer_documents}
result = json.loads(open_badge_ob3_verify(json.dumps(request)))
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
