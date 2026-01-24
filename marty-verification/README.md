# marty-verification-py

Python bindings for the `marty-verification` Rust library, providing cryptographic verification and Open Badges support.

## Features

- **Open Badges**: Issue and verify Open Badges v2 and v3 credentials
- **mDoc/mDL Verification**: Verify mobile driver's licenses (ISO 18013-5)
- **eMRTD Verification**: Verify electronic machine-readable travel documents
- **MRZ Parsing**: Parse and validate machine-readable zone data
- **Certificate Operations**: Build and verify X.509 certificate chains
- **Cryptographic Primitives**: Ed25519, P-256, RSA, hashing, JWK/JWS/JWE

## Installation

```bash
pip install marty-verification-py
```

## Usage

### Open Badges

```python
from marty_verification_py import open_badge_ob2_issue, open_badge_ob2_verify

# Issue an Open Badge v2 credential
request = {
    "assertion": {
        "@context": "https://w3id.org/openbadges/v2",
        "type": "Assertion",
        "badge": {...},
        "recipient": {"identity": "user@example.com", "type": "email"}
    },
    "signing": {
        "jwk": {...},
        "alg": "ES256"
    }
}
result = open_badge_ob2_issue(json.dumps(request))
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
