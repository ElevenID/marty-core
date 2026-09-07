# marty-crypto

Verification and explicitly scoped protocol-session cryptography for Marty.

Production builds have no key-generation, signing, private-key codec,
PKCS#12, BBS signing, or certificate/SOD builder feature. Credential signing
uses prepare/KMS/assemble APIs in the service layer. Local fixtures live in the
non-publishable `marty-crypto-test-support` crate.

```toml
[dependencies]
marty-crypto = { version = "0.2", default-features = false, features = ["signature-verification", "x509"] }
```

| Feature | Capability |
| --- | --- |
| `signature-verification` | ECDSA, EdDSA, and RSA verification |
| `bbs-verification` | BBS signature/proof verification and holder proof generation |
| `x509` | X.509 parsing and signature verification |
| `crl` | CRL parsing and verification |
| `ocsp` | OCSP parsing and verification |
| `public-key-codec` | Public SPKI/PEM codecs |
| `ecdh` | Explicit ephemeral key agreement |
| `symmetric` | Explicit protocol-session encryption |
| `kdf` | HKDF and PBKDF2 |

All features are off by default. Session capabilities must be selected by the
product crate that owns the protocol session.

```rust
use marty_crypto::{ecdsa::verify_p256_sha256, serialization::load_public_key_pem};

let public_key = load_public_key_pem(public_key_pem)?;
let valid = verify_p256_sha256(&public_key, message, signature)?;
```

Licensed under MIT OR Apache-2.0 at your option.
