# marty-crypto

Pure cryptographic primitives for the Marty ecosystem.

## Overview

`marty-crypto` provides low-level cryptographic operations used throughout Marty products:

- **Signature algorithms**: ECDSA (P-256/P-384/P-521), EdDSA (Ed25519, Ed448), RSA (PKCS#1 v1.5, PSS)
- **X.509 certificates**: Parsing, information extraction, chain building
- **Symmetric encryption**: AES-GCM, AES-CBC, 3DES (legacy)
- **Key derivation**: HKDF, PBKDF2
- **Key agreement**: ECDH (X25519)
- **Certificate revocation**: CRL parsing, OCSP response parsing

## Features

```toml
[dependencies]
marty-crypto = { version = "0.1", features = ["full"] }
```

| Feature | Description | Default |
|---------|-------------|---------|
| `ecdsa` | ECDSA with P-256/P-384/P-521 | ✅ |
| `eddsa` | Ed25519 and Ed448 | ✅ |
| `rsa` | RSA PKCS#1 v1.5 and PSS | ✅ |
| `x509` | X.509 certificate parsing | ✅ |
| `symmetric` | AES-GCM, AES-CBC, 3DES | ❌ |
| `kdf` | HKDF, PBKDF2 | ❌ |
| `pkcs12` | PKCS#12 bundle parsing | ❌ |
| `full` | All features | ❌ |

## Usage

```rust
use marty_crypto::{
    ecdsa::{generate_p256_keypair, sign_p256, verify_p256},
    certificate::{load_certificate_pem, get_certificate_info},
    HashAlgorithm, SignatureAlgorithm,
};

// Generate a key pair
let (private_key, public_key) = generate_p256_keypair()?;

// Sign a message
let message = b"Hello, World!";
let signature = sign_p256(&private_key, message)?;

// Verify the signature
verify_p256(&public_key, message, &signature)?;
```

## Design Principles

- **No policy decisions**: This crate provides cryptographic primitives only. Verification policies (trust anchors, revocation checking) belong in `marty-verification`.
- **No network I/O**: All operations are synchronous and local. Network clients (OCSP, PKD) belong in higher-level crates.
- **Minimal dependencies**: Uses RustCrypto crates exclusively for pure Rust implementation.

## License

Licensed under MIT OR Apache-2.0 at your option.
