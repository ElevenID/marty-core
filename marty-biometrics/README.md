# marty-biometrics

Biometric verification for the Marty ecosystem.

## Features

- **Face Verification**: 1:1 face matching with configurable thresholds
- **Quality Assessment**: Image quality evaluation for optimal verification
- **Liveness Detection**: Anti-spoofing with challenge-response protocol
- **Pluggable Providers**: Support for local and commercial providers (SITA, NEC, Idemia)
- **Multi-platform**: Native Rust, Python bindings (PyO3), and WebAssembly

## Installation

### Rust

Add to your `Cargo.toml`:

```toml
[dependencies]
marty-biometrics = { git = "https://github.com/ElevenID/marty-core", features = ["native"] }
```

### Python

```bash
# Install from wheel
pip install marty-biometrics

# Or build from source
cd marty-biometrics
make dev-python
```

Compiled Python extensions are Maturin build/release artifacts, not source files.
Install a platform wheel or build from the Rust sources before using the native
API; a source-only checkout reports unavailable bindings until that build/install.
Do not commit generated `.so` or `.pyd` files. Release wheel preflight checks the
installed extension and public adapter from a source build.

### WebAssembly

```bash
make build-wasm
# Output in pkg/
```

## Usage

### Rust

```rust
use marty_biometrics::{BiometricProvider, FaceVerifier, FaceVerificationRequest};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a provider (mock for testing, local for production)
    let provider = BiometricProvider::mock();
    
    // Create verification request
    let request = FaceVerificationRequest {
        reference_image: "base64_encoded_credential_photo".to_string(),
        probe_image: "base64_encoded_live_capture".to_string(),
        threshold: Some(0.7),
        ..Default::default()
    };
    
    // Verify
    let result = provider.verify(request).await?;
    println!("Verified: {}, Similarity: {:.2}", result.verified, result.similarity);
    
    Ok(())
}
```

### Python

```python
from marty_biometrics import FaceVerificationRequest
from marty_biometrics.adapters.rust import RustFaceVerifier

# Create verifier
verifier = RustFaceVerifier.mock()

# Check capabilities
caps = verifier.capabilities()
print(f"Provider: {caps.name} v{caps.version}")

# Verify faces
request = FaceVerificationRequest(
    reference_image="base64_encoded_credential_photo",
    probe_image="base64_encoded_live_capture",
    threshold=0.7,
)
result = verifier.verify(request)
print(f"Verified: {result.verified}, Similarity: {result.similarity:.2f}")
```

### JavaScript/TypeScript (WASM)

```javascript
import init, { 
    create_verification_request,
    version 
} from 'marty-biometrics';

await init();

console.log(`marty-biometrics v${version()}`);

const request = create_verification_request(
    referenceImageBase64,
    probeImageBase64,
    0.7
);
```

## Feature Flags

| Feature | Description |
|---------|-------------|
| `native` | Async runtime and image processing for native builds |
| `python` | Python bindings via PyO3 |
| `wasm` | WebAssembly bindings via wasm-bindgen |
| `liveness` | Liveness challenge signing and validation |
| `opencv` | Local OpenCV-based face matching (placeholder) |
| `sita` | SITA provider integration (placeholder) |
| `nec` | NEC provider integration (placeholder) |
| `idemia` | Idemia provider integration (placeholder) |

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Applications                         │
│  (marty-verifier, marty-credentials, web apps, etc.)   │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                  marty-biometrics                       │
│                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │   Types     │  │   Traits    │  │  Liveness   │     │
│  │ (Request,   │  │ (FaceVeri-  │  │ (Challenge  │     │
│  │  Result)    │  │   fier)     │  │  Builder)   │     │
│  └─────────────┘  └─────────────┘  └─────────────┘     │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │              Provider Implementations            │   │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────────────┐  │   │
│  │  │  Mock   │  │  Local  │  │ SITA/NEC/Idemia │  │   │
│  │  └─────────┘  └─────────┘  └─────────────────┘  │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

## Development

```bash
# Run tests
make test

# Build Python bindings (dev mode)
make dev-python

# Build WASM package
make build-wasm

# Lint
make lint

# Format
make fmt
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](../LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](../LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
