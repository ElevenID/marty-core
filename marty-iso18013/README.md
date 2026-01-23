# marty-iso18013

ISO 18013-5 mobile driving license (mDL) protocol implementation in Rust.

## Overview

This crate provides a complete implementation of ISO 18013-5, the international standard for mobile driving licenses. It includes:

- **Device Engagement**: QR code generation and connection setup
- **Session Management**: ECDH key agreement and AES-256-GCM encryption
- **Protocol Flows**: Request/response handling with state machine
- **Selective Disclosure**: Privacy-preserving data presentation
- **Transport Layers**: BLE, NFC, and HTTPS support
- **Applications**: Holder (wallet) and Reader (verifier) implementations

## Features

- `python`: PyO3 bindings for Python integration
- `ble`: Bluetooth Low Energy transport
- `nfc`: Near Field Communication transport
- `all-transports`: Enable all transport layers

## Usage

```rust
use marty_iso18013::{DeviceEngagement, Session, SessionConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create device engagement
    let mut engagement = DeviceEngagement::new_qr()?;
    engagement.add_ble_transport("0000FFF0-0000-1000-8000-00805F9B34FB")?;
    
    // Generate QR code
    let qr_code = engagement.to_qr_code()?;
    
    // Establish session
    let config = SessionConfig::default();
    let session = Session::from_engagement(&engagement, config).await?;
    
    Ok(())
}
```

## Python Bindings

```python
from marty_iso18013 import DeviceEngagement, Session, SessionConfig

# Create engagement
engagement = DeviceEngagement.new()
engagement.add_ble("0000FFF0-0000-1000-8000-00805F9B34FB")

# Establish session
config = SessionConfig()
session = Session.from_engagement(engagement, config)
```

## Architecture

- `core`: Device engagement and protocol structures
- `session`: ECDH key agreement and session encryption
- `protocol`: Protocol state machine and message handling
- `selective`: Selective disclosure logic
- `transport`: Transport layer abstractions (BLE, NFC, HTTPS)
- `apps`: Holder and Reader applications

## Dependencies

- `marty-crypto`: Cryptographic operations (ECDH, AES-GCM, HKDF)
- `marty-verification`: mDL verification and trust chains
- `marty-types`: Shared constants and types
- `isomdl`: ISO 18013-5 data structures
- `btleplug`: BLE transport (optional)
- `pcsc`: NFC transport (optional)

## Testing

```bash
cargo test
cargo test --all-features
```

## License

MIT OR Apache-2.0
