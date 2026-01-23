# marty-types

Shared type definitions and constants for the Marty ecosystem.

## Overview

This crate provides centralized type definitions, constants, and error codes used across Marty components. It uses **schema-based code generation** to ensure consistency across Rust, Python, and Dart.

## Features

- **ISO 18013-5 mDL constants**: Namespaces, document types, data elements
- **W3C Verifiable Credentials**: Context URIs and credential types
- **Credential formats**: Format identifiers (JWT, mDoc, SD-JWT, etc.)
- **Hierarchical error codes**: Structured error codes with metadata
- **Multi-language support**: Generates code for Rust, Python, and Dart

## Usage

### Rust

```rust
use marty_types::namespaces::iso18013;

let namespace = iso18013::namespace::MDL; // "org.iso.18013.5.1"
let doc_type = iso18013::doc_type::MDL;   // "org.iso.18013.5.1.mDL"
let element = iso18013::element::FAMILY_NAME; // "family_name"
```

### Python

```python
from marty_types import Iso18013Namespace, Iso18013Element

namespace = Iso18013Namespace.MDL  # "org.iso.18013.5.1"
element = Iso18013Element.FAMILY_NAME  # "family_name"
```

### Dart

```dart
import 'package:marty_types/namespaces.dart';

final namespace = Iso18013Namespace.mdl;  // "org.iso.18013.5.1"
final element = Iso18013Element.familyName;  // "family_name"
```

## Code Generation

The code is generated from YAML schemas in the `schema/` directory:

```bash
# Install dependencies
pip install pyyaml jinja2

# Generate code for all languages
python codegen/generate.py

# Format Rust code
cargo fmt
```

### Schema Files

- `schema/namespaces.yaml`: ISO 18013, W3C, and credential format constants
- `schema/error_codes.yaml`: Hierarchical error code definitions

## Development

### Adding New Constants

1. Edit the appropriate YAML file in `schema/`
2. Run `python codegen/generate.py`
3. Run `cargo fmt`
4. Commit both the schema and generated files

### CI Integration

The CI pipeline checks that generated code is up-to-date:

```yaml
- name: Check generated types are current
  run: |
    cd marty-types
    python codegen/generate.py
    git diff --exit-code
```

## License

MIT OR Apache-2.0
