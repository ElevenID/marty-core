# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [unreleased] - 2026-03-27

### Bug Fixes

- Auto-format code to pass CI checks ([bb7179a](bb7179a8fd5ae80e049db41121e706c015e3ecf9))
- Resolve clippy warnings and compilation errors ([3ac1390](3ac1390fd872f9ee0ef3bddff4219042ac4ff78f))
- Gate chip_io module behind csca feature ([4e0ebae](4e0ebae179a59a70536302650b5b79c986457cf6))
- Update CI workflow for Python tests and feature testing ([1fb3f8e](1fb3f8e4219c3ec34b1f613867ee72ee82540844))
- Add placeholder Python tests and fix pytest path ([83f0aa8](83f0aa85b3d7c3b7b46b30d01721eec7c0b708c8))
- Gate testdata module behind test-fixtures feature ([94d069a](94d069a7ea9a391291b0f26951eeb0bcb851b208))
- Correct relative paths in testdata.rs for include_bytes ([9d26b61](9d26b614c2c94bed1460624e96ac22c751247608))
- Add CHANGELOG.md and fix git-cliff config path ([c9ab7c9](c9ab7c91d2ae87509a9487f884edb2c5205ee514))
- CI improvements - proper feature flags, Windows Python tests, remove MSRV matrix ([e08e449](e08e449565790481786e96131c3a50ae4c6c7bd7))
- Use bundled-sqlcipher-vendored-openssl for Windows compatibility ([0b8b558](0b8b5584d4569eba697852bfa16b834d75fbefce))
- **marty-zkp**: Select highest-version spec; test against real Longfellow library ([dea921d](dea921d5aac76f090cfe82f1b346001de1483fd6))

### Features

- Add automated release pipeline with RC staging ([475fca2](475fca2b5b579b011fe49a4b404c34afec7fd233))
- Add NIST PKITS test fixtures for certificate validation ([d9e050e](d9e050ec9a34e6a3ce1d65d819f7df513761f42d))
- Add Open Badges support and ZKP module ([b3cfb97](b3cfb9734c2ff3c614796e8b8f21215b18adc4d0))
- Add marty-bindings crate with PyO3 0.22 compatibility ([82321b3](82321b38ccf479c5f5eee472e1475ae0c5845dc1))
- **oid4vci**: Add OID4VCI module and update ZKP mock implementation ([beda752](beda752f039a674a03cfe19e02d53a804139fb52))
- **marty-zkp**: Replace mock with real Longfellow ZK C API ([117d1be](117d1bead0c14ca783ade1101393f285d90f2e21))
- **oid4vci,verification**: Add OID4VCI verifier, SD-JWT VC support, and CAVP/conformance test suites ([e130a0a](e130a0ae306a842d7bda05a052fa124d9931a6c4))
- GRPC migration, Cedar authorization, BBS crypto, OID4VC conformance, and service layer enhancements ([025cefb](025cefb5fc69d03b68e589231c66be1c6cd3c213))

### Miscellaneous Tasks

- Update CHANGELOG.md ([1941514](194151407f6169e8d7b0befa56757bdb39fe5ed8))
- Update CHANGELOG.md ([629f286](629f28682954001551060c26936590b3fa3a94a5))
- Update CHANGELOG.md ([2135f22](2135f22bf7205dbb6f7d2f442186f339cbc8de1b))
- Update CHANGELOG.md ([df222cb](df222cbf44d07879525621acfc7d1c429ddff21e))
- Update CHANGELOG.md ([a9488b9](a9488b97b63f6a7fd30b20cf6c562066cf36a100))
- Update CHANGELOG.md ([2f33a48](2f33a4881e65cb0b1de7f7c0fcfad86e5ec0a693))
- Update CHANGELOG.md ([cc18d69](cc18d69c9d40a22300a4fade0f780d7216e7b9f5))
- Update CHANGELOG.md ([8fce0d3](8fce0d30ae083dc92ffdbcda65175b624643488e))
- Commit generated types for git dep compatibility ([b375db3](b375db36900347f139679feebdb3490ae466ee41))
- Update CHANGELOG.md ([ea12e5d](ea12e5d246b99d27d4fead84f9a090160e16e86c))
- Update CHANGELOG.md ([1e25b66](1e25b66e90a0580a3ebd3226d97de9d1cba4bf32))

### Security

- Add comprehensive security and quality checks ([2826d48](2826d48a7d81d8943f77b8a40c6dfaa93b21950f))
- Make security checks non-blocking to prevent repeated failures ([b5c7091](b5c7091dd2c66c85b5bca0e1323d16d988c82218))

### Testing

- **marty-zkp**: Multi-attribute coverage + attribute count validation ([0050122](005012210c90ad863855e633dfbc2b5336ffed98))

### Ci

- Enable all features including test-fixtures in CI ([fbc9ecd](fbc9ecdb373929b223b867a03d09b0b110e9a48a))
- Add repository_dispatch to notify downstream repos on release ([f21287e](f21287e22a1f7d7ac53112dc4aabe6f18f538de7))
- Use REPO_ACCESS_TOKEN for cross-repo dispatch ([438d0f8](438d0f817b6f6c5e19827045d92d4bf28280eb99))

### Security

- **marty-zkp**: Hard-block ZK mock from release builds ([53c2d35](53c2d354f56c980c9595fac0f98e064e46e576ed))

## [unreleased] - 2026-03-27

### Bug Fixes

- Auto-format code to pass CI checks ([bb7179a](bb7179a8fd5ae80e049db41121e706c015e3ecf9))
- Resolve clippy warnings and compilation errors ([3ac1390](3ac1390fd872f9ee0ef3bddff4219042ac4ff78f))
- Gate chip_io module behind csca feature ([4e0ebae](4e0ebae179a59a70536302650b5b79c986457cf6))
- Update CI workflow for Python tests and feature testing ([1fb3f8e](1fb3f8e4219c3ec34b1f613867ee72ee82540844))
- Add placeholder Python tests and fix pytest path ([83f0aa8](83f0aa85b3d7c3b7b46b30d01721eec7c0b708c8))
- Gate testdata module behind test-fixtures feature ([94d069a](94d069a7ea9a391291b0f26951eeb0bcb851b208))
- Correct relative paths in testdata.rs for include_bytes ([9d26b61](9d26b614c2c94bed1460624e96ac22c751247608))
- Add CHANGELOG.md and fix git-cliff config path ([c9ab7c9](c9ab7c91d2ae87509a9487f884edb2c5205ee514))
- CI improvements - proper feature flags, Windows Python tests, remove MSRV matrix ([e08e449](e08e449565790481786e96131c3a50ae4c6c7bd7))
- Use bundled-sqlcipher-vendored-openssl for Windows compatibility ([0b8b558](0b8b5584d4569eba697852bfa16b834d75fbefce))
- **marty-zkp**: Select highest-version spec; test against real Longfellow library ([dea921d](dea921d5aac76f090cfe82f1b346001de1483fd6))

### Features

- Add automated release pipeline with RC staging ([475fca2](475fca2b5b579b011fe49a4b404c34afec7fd233))
- Add NIST PKITS test fixtures for certificate validation ([d9e050e](d9e050ec9a34e6a3ce1d65d819f7df513761f42d))
- Add Open Badges support and ZKP module ([b3cfb97](b3cfb9734c2ff3c614796e8b8f21215b18adc4d0))
- Add marty-bindings crate with PyO3 0.22 compatibility ([82321b3](82321b38ccf479c5f5eee472e1475ae0c5845dc1))
- **oid4vci**: Add OID4VCI module and update ZKP mock implementation ([beda752](beda752f039a674a03cfe19e02d53a804139fb52))
- **marty-zkp**: Replace mock with real Longfellow ZK C API ([117d1be](117d1bead0c14ca783ade1101393f285d90f2e21))
- **oid4vci,verification**: Add OID4VCI verifier, SD-JWT VC support, and CAVP/conformance test suites ([e130a0a](e130a0ae306a842d7bda05a052fa124d9931a6c4))
- GRPC migration, Cedar authorization, BBS crypto, OID4VC conformance, and service layer enhancements ([025cefb](025cefb5fc69d03b68e589231c66be1c6cd3c213))

### Miscellaneous Tasks

- Update CHANGELOG.md ([1941514](194151407f6169e8d7b0befa56757bdb39fe5ed8))
- Update CHANGELOG.md ([629f286](629f28682954001551060c26936590b3fa3a94a5))
- Update CHANGELOG.md ([2135f22](2135f22bf7205dbb6f7d2f442186f339cbc8de1b))
- Update CHANGELOG.md ([df222cb](df222cbf44d07879525621acfc7d1c429ddff21e))
- Update CHANGELOG.md ([a9488b9](a9488b97b63f6a7fd30b20cf6c562066cf36a100))
- Update CHANGELOG.md ([2f33a48](2f33a4881e65cb0b1de7f7c0fcfad86e5ec0a693))
- Update CHANGELOG.md ([cc18d69](cc18d69c9d40a22300a4fade0f780d7216e7b9f5))
- Update CHANGELOG.md ([8fce0d3](8fce0d30ae083dc92ffdbcda65175b624643488e))
- Commit generated types for git dep compatibility ([b375db3](b375db36900347f139679feebdb3490ae466ee41))
- Update CHANGELOG.md ([ea12e5d](ea12e5d246b99d27d4fead84f9a090160e16e86c))

### Security

- Add comprehensive security and quality checks ([2826d48](2826d48a7d81d8943f77b8a40c6dfaa93b21950f))
- Make security checks non-blocking to prevent repeated failures ([b5c7091](b5c7091dd2c66c85b5bca0e1323d16d988c82218))

### Testing

- **marty-zkp**: Multi-attribute coverage + attribute count validation ([0050122](005012210c90ad863855e633dfbc2b5336ffed98))

### Ci

- Enable all features including test-fixtures in CI ([fbc9ecd](fbc9ecdb373929b223b867a03d09b0b110e9a48a))
- Add repository_dispatch to notify downstream repos on release ([f21287e](f21287e22a1f7d7ac53112dc4aabe6f18f538de7))

### Security

- **marty-zkp**: Hard-block ZK mock from release builds ([53c2d35](53c2d354f56c980c9595fac0f98e064e46e576ed))

## [unreleased] - 2026-03-27

### Bug Fixes

- Auto-format code to pass CI checks ([bb7179a](bb7179a8fd5ae80e049db41121e706c015e3ecf9))
- Resolve clippy warnings and compilation errors ([3ac1390](3ac1390fd872f9ee0ef3bddff4219042ac4ff78f))
- Gate chip_io module behind csca feature ([4e0ebae](4e0ebae179a59a70536302650b5b79c986457cf6))
- Update CI workflow for Python tests and feature testing ([1fb3f8e](1fb3f8e4219c3ec34b1f613867ee72ee82540844))
- Add placeholder Python tests and fix pytest path ([83f0aa8](83f0aa85b3d7c3b7b46b30d01721eec7c0b708c8))
- Gate testdata module behind test-fixtures feature ([94d069a](94d069a7ea9a391291b0f26951eeb0bcb851b208))
- Correct relative paths in testdata.rs for include_bytes ([9d26b61](9d26b614c2c94bed1460624e96ac22c751247608))
- Add CHANGELOG.md and fix git-cliff config path ([c9ab7c9](c9ab7c91d2ae87509a9487f884edb2c5205ee514))
- CI improvements - proper feature flags, Windows Python tests, remove MSRV matrix ([e08e449](e08e449565790481786e96131c3a50ae4c6c7bd7))
- Use bundled-sqlcipher-vendored-openssl for Windows compatibility ([0b8b558](0b8b5584d4569eba697852bfa16b834d75fbefce))
- **marty-zkp**: Select highest-version spec; test against real Longfellow library ([dea921d](dea921d5aac76f090cfe82f1b346001de1483fd6))

### Features

- Add automated release pipeline with RC staging ([475fca2](475fca2b5b579b011fe49a4b404c34afec7fd233))
- Add NIST PKITS test fixtures for certificate validation ([d9e050e](d9e050ec9a34e6a3ce1d65d819f7df513761f42d))
- Add Open Badges support and ZKP module ([b3cfb97](b3cfb9734c2ff3c614796e8b8f21215b18adc4d0))
- Add marty-bindings crate with PyO3 0.22 compatibility ([82321b3](82321b38ccf479c5f5eee472e1475ae0c5845dc1))
- **oid4vci**: Add OID4VCI module and update ZKP mock implementation ([beda752](beda752f039a674a03cfe19e02d53a804139fb52))
- **marty-zkp**: Replace mock with real Longfellow ZK C API ([117d1be](117d1bead0c14ca783ade1101393f285d90f2e21))
- **oid4vci,verification**: Add OID4VCI verifier, SD-JWT VC support, and CAVP/conformance test suites ([e130a0a](e130a0ae306a842d7bda05a052fa124d9931a6c4))
- GRPC migration, Cedar authorization, BBS crypto, OID4VC conformance, and service layer enhancements ([025cefb](025cefb5fc69d03b68e589231c66be1c6cd3c213))

### Miscellaneous Tasks

- Update CHANGELOG.md ([1941514](194151407f6169e8d7b0befa56757bdb39fe5ed8))
- Update CHANGELOG.md ([629f286](629f28682954001551060c26936590b3fa3a94a5))
- Update CHANGELOG.md ([2135f22](2135f22bf7205dbb6f7d2f442186f339cbc8de1b))
- Update CHANGELOG.md ([df222cb](df222cbf44d07879525621acfc7d1c429ddff21e))
- Update CHANGELOG.md ([a9488b9](a9488b97b63f6a7fd30b20cf6c562066cf36a100))
- Update CHANGELOG.md ([2f33a48](2f33a4881e65cb0b1de7f7c0fcfad86e5ec0a693))
- Update CHANGELOG.md ([cc18d69](cc18d69c9d40a22300a4fade0f780d7216e7b9f5))
- Update CHANGELOG.md ([8fce0d3](8fce0d30ae083dc92ffdbcda65175b624643488e))
- Commit generated types for git dep compatibility ([b375db3](b375db36900347f139679feebdb3490ae466ee41))

### Security

- Add comprehensive security and quality checks ([2826d48](2826d48a7d81d8943f77b8a40c6dfaa93b21950f))
- Make security checks non-blocking to prevent repeated failures ([b5c7091](b5c7091dd2c66c85b5bca0e1323d16d988c82218))

### Testing

- **marty-zkp**: Multi-attribute coverage + attribute count validation ([0050122](005012210c90ad863855e633dfbc2b5336ffed98))

### Ci

- Enable all features including test-fixtures in CI ([fbc9ecd](fbc9ecdb373929b223b867a03d09b0b110e9a48a))

### Security

- **marty-zkp**: Hard-block ZK mock from release builds ([53c2d35](53c2d354f56c980c9595fac0f98e064e46e576ed))

## [unreleased] - 2026-03-18

### Bug Fixes

- Auto-format code to pass CI checks ([bb7179a](bb7179a8fd5ae80e049db41121e706c015e3ecf9))
- Resolve clippy warnings and compilation errors ([3ac1390](3ac1390fd872f9ee0ef3bddff4219042ac4ff78f))
- Gate chip_io module behind csca feature ([4e0ebae](4e0ebae179a59a70536302650b5b79c986457cf6))
- Update CI workflow for Python tests and feature testing ([1fb3f8e](1fb3f8e4219c3ec34b1f613867ee72ee82540844))
- Add placeholder Python tests and fix pytest path ([83f0aa8](83f0aa85b3d7c3b7b46b30d01721eec7c0b708c8))
- Gate testdata module behind test-fixtures feature ([94d069a](94d069a7ea9a391291b0f26951eeb0bcb851b208))
- Correct relative paths in testdata.rs for include_bytes ([9d26b61](9d26b614c2c94bed1460624e96ac22c751247608))
- Add CHANGELOG.md and fix git-cliff config path ([c9ab7c9](c9ab7c91d2ae87509a9487f884edb2c5205ee514))
- CI improvements - proper feature flags, Windows Python tests, remove MSRV matrix ([e08e449](e08e449565790481786e96131c3a50ae4c6c7bd7))
- Use bundled-sqlcipher-vendored-openssl for Windows compatibility ([0b8b558](0b8b5584d4569eba697852bfa16b834d75fbefce))
- **marty-zkp**: Select highest-version spec; test against real Longfellow library ([dea921d](dea921d5aac76f090cfe82f1b346001de1483fd6))

### Features

- Add automated release pipeline with RC staging ([475fca2](475fca2b5b579b011fe49a4b404c34afec7fd233))
- Add NIST PKITS test fixtures for certificate validation ([d9e050e](d9e050ec9a34e6a3ce1d65d819f7df513761f42d))
- Add Open Badges support and ZKP module ([b3cfb97](b3cfb9734c2ff3c614796e8b8f21215b18adc4d0))
- Add marty-bindings crate with PyO3 0.22 compatibility ([82321b3](82321b38ccf479c5f5eee472e1475ae0c5845dc1))
- **oid4vci**: Add OID4VCI module and update ZKP mock implementation ([beda752](beda752f039a674a03cfe19e02d53a804139fb52))
- **marty-zkp**: Replace mock with real Longfellow ZK C API ([117d1be](117d1bead0c14ca783ade1101393f285d90f2e21))
- **oid4vci,verification**: Add OID4VCI verifier, SD-JWT VC support, and CAVP/conformance test suites ([e130a0a](e130a0ae306a842d7bda05a052fa124d9931a6c4))
- GRPC migration, Cedar authorization, BBS crypto, OID4VC conformance, and service layer enhancements ([025cefb](025cefb5fc69d03b68e589231c66be1c6cd3c213))

### Miscellaneous Tasks

- Update CHANGELOG.md ([1941514](194151407f6169e8d7b0befa56757bdb39fe5ed8))
- Update CHANGELOG.md ([629f286](629f28682954001551060c26936590b3fa3a94a5))
- Update CHANGELOG.md ([2135f22](2135f22bf7205dbb6f7d2f442186f339cbc8de1b))
- Update CHANGELOG.md ([df222cb](df222cbf44d07879525621acfc7d1c429ddff21e))
- Update CHANGELOG.md ([a9488b9](a9488b97b63f6a7fd30b20cf6c562066cf36a100))
- Update CHANGELOG.md ([2f33a48](2f33a4881e65cb0b1de7f7c0fcfad86e5ec0a693))
- Update CHANGELOG.md ([cc18d69](cc18d69c9d40a22300a4fade0f780d7216e7b9f5))

### Security

- Add comprehensive security and quality checks ([2826d48](2826d48a7d81d8943f77b8a40c6dfaa93b21950f))
- Make security checks non-blocking to prevent repeated failures ([b5c7091](b5c7091dd2c66c85b5bca0e1323d16d988c82218))

### Testing

- **marty-zkp**: Multi-attribute coverage + attribute count validation ([0050122](005012210c90ad863855e633dfbc2b5336ffed98))

### Ci

- Enable all features including test-fixtures in CI ([fbc9ecd](fbc9ecdb373929b223b867a03d09b0b110e9a48a))

### Security

- **marty-zkp**: Hard-block ZK mock from release builds ([53c2d35](53c2d354f56c980c9595fac0f98e064e46e576ed))

## [unreleased] - 2026-03-12

### Bug Fixes

- Auto-format code to pass CI checks ([bb7179a](bb7179a8fd5ae80e049db41121e706c015e3ecf9))
- Resolve clippy warnings and compilation errors ([3ac1390](3ac1390fd872f9ee0ef3bddff4219042ac4ff78f))
- Gate chip_io module behind csca feature ([4e0ebae](4e0ebae179a59a70536302650b5b79c986457cf6))
- Update CI workflow for Python tests and feature testing ([1fb3f8e](1fb3f8e4219c3ec34b1f613867ee72ee82540844))
- Add placeholder Python tests and fix pytest path ([83f0aa8](83f0aa85b3d7c3b7b46b30d01721eec7c0b708c8))
- Gate testdata module behind test-fixtures feature ([94d069a](94d069a7ea9a391291b0f26951eeb0bcb851b208))
- Correct relative paths in testdata.rs for include_bytes ([9d26b61](9d26b614c2c94bed1460624e96ac22c751247608))
- Add CHANGELOG.md and fix git-cliff config path ([c9ab7c9](c9ab7c91d2ae87509a9487f884edb2c5205ee514))
- CI improvements - proper feature flags, Windows Python tests, remove MSRV matrix ([e08e449](e08e449565790481786e96131c3a50ae4c6c7bd7))
- Use bundled-sqlcipher-vendored-openssl for Windows compatibility ([0b8b558](0b8b5584d4569eba697852bfa16b834d75fbefce))
- **marty-zkp**: Select highest-version spec; test against real Longfellow library ([dea921d](dea921d5aac76f090cfe82f1b346001de1483fd6))

### Features

- Add automated release pipeline with RC staging ([475fca2](475fca2b5b579b011fe49a4b404c34afec7fd233))
- Add NIST PKITS test fixtures for certificate validation ([d9e050e](d9e050ec9a34e6a3ce1d65d819f7df513761f42d))
- Add Open Badges support and ZKP module ([b3cfb97](b3cfb9734c2ff3c614796e8b8f21215b18adc4d0))
- Add marty-bindings crate with PyO3 0.22 compatibility ([82321b3](82321b38ccf479c5f5eee472e1475ae0c5845dc1))
- **oid4vci**: Add OID4VCI module and update ZKP mock implementation ([beda752](beda752f039a674a03cfe19e02d53a804139fb52))
- **marty-zkp**: Replace mock with real Longfellow ZK C API ([117d1be](117d1bead0c14ca783ade1101393f285d90f2e21))
- **oid4vci,verification**: Add OID4VCI verifier, SD-JWT VC support, and CAVP/conformance test suites ([e130a0a](e130a0ae306a842d7bda05a052fa124d9931a6c4))

### Miscellaneous Tasks

- Update CHANGELOG.md ([1941514](194151407f6169e8d7b0befa56757bdb39fe5ed8))
- Update CHANGELOG.md ([629f286](629f28682954001551060c26936590b3fa3a94a5))
- Update CHANGELOG.md ([2135f22](2135f22bf7205dbb6f7d2f442186f339cbc8de1b))
- Update CHANGELOG.md ([df222cb](df222cbf44d07879525621acfc7d1c429ddff21e))
- Update CHANGELOG.md ([a9488b9](a9488b97b63f6a7fd30b20cf6c562066cf36a100))
- Update CHANGELOG.md ([2f33a48](2f33a4881e65cb0b1de7f7c0fcfad86e5ec0a693))

### Security

- Add comprehensive security and quality checks ([2826d48](2826d48a7d81d8943f77b8a40c6dfaa93b21950f))
- Make security checks non-blocking to prevent repeated failures ([b5c7091](b5c7091dd2c66c85b5bca0e1323d16d988c82218))

### Testing

- **marty-zkp**: Multi-attribute coverage + attribute count validation ([0050122](005012210c90ad863855e633dfbc2b5336ffed98))

### Ci

- Enable all features including test-fixtures in CI ([fbc9ecd](fbc9ecdb373929b223b867a03d09b0b110e9a48a))

### Security

- **marty-zkp**: Hard-block ZK mock from release builds ([53c2d35](53c2d354f56c980c9595fac0f98e064e46e576ed))

## [unreleased] - 2026-03-02

### Bug Fixes

- Auto-format code to pass CI checks ([bb7179a](bb7179a8fd5ae80e049db41121e706c015e3ecf9))
- Resolve clippy warnings and compilation errors ([3ac1390](3ac1390fd872f9ee0ef3bddff4219042ac4ff78f))
- Gate chip_io module behind csca feature ([4e0ebae](4e0ebae179a59a70536302650b5b79c986457cf6))
- Update CI workflow for Python tests and feature testing ([1fb3f8e](1fb3f8e4219c3ec34b1f613867ee72ee82540844))
- Add placeholder Python tests and fix pytest path ([83f0aa8](83f0aa85b3d7c3b7b46b30d01721eec7c0b708c8))
- Gate testdata module behind test-fixtures feature ([94d069a](94d069a7ea9a391291b0f26951eeb0bcb851b208))
- Correct relative paths in testdata.rs for include_bytes ([9d26b61](9d26b614c2c94bed1460624e96ac22c751247608))
- Add CHANGELOG.md and fix git-cliff config path ([c9ab7c9](c9ab7c91d2ae87509a9487f884edb2c5205ee514))
- CI improvements - proper feature flags, Windows Python tests, remove MSRV matrix ([e08e449](e08e449565790481786e96131c3a50ae4c6c7bd7))
- Use bundled-sqlcipher-vendored-openssl for Windows compatibility ([0b8b558](0b8b5584d4569eba697852bfa16b834d75fbefce))

### Features

- Add automated release pipeline with RC staging ([475fca2](475fca2b5b579b011fe49a4b404c34afec7fd233))
- Add NIST PKITS test fixtures for certificate validation ([d9e050e](d9e050ec9a34e6a3ce1d65d819f7df513761f42d))
- Add Open Badges support and ZKP module ([b3cfb97](b3cfb9734c2ff3c614796e8b8f21215b18adc4d0))
- Add marty-bindings crate with PyO3 0.22 compatibility ([82321b3](82321b38ccf479c5f5eee472e1475ae0c5845dc1))
- **oid4vci**: Add OID4VCI module and update ZKP mock implementation ([beda752](beda752f039a674a03cfe19e02d53a804139fb52))

### Miscellaneous Tasks

- Update CHANGELOG.md ([1941514](194151407f6169e8d7b0befa56757bdb39fe5ed8))
- Update CHANGELOG.md ([629f286](629f28682954001551060c26936590b3fa3a94a5))
- Update CHANGELOG.md ([2135f22](2135f22bf7205dbb6f7d2f442186f339cbc8de1b))
- Update CHANGELOG.md ([df222cb](df222cbf44d07879525621acfc7d1c429ddff21e))
- Update CHANGELOG.md ([a9488b9](a9488b97b63f6a7fd30b20cf6c562066cf36a100))

### Security

- Add comprehensive security and quality checks ([2826d48](2826d48a7d81d8943f77b8a40c6dfaa93b21950f))
- Make security checks non-blocking to prevent repeated failures ([b5c7091](b5c7091dd2c66c85b5bca0e1323d16d988c82218))

### Ci

- Enable all features including test-fixtures in CI ([fbc9ecd](fbc9ecdb373929b223b867a03d09b0b110e9a48a))

## [unreleased] - 2026-02-07

### Bug Fixes

- Auto-format code to pass CI checks ([bb7179a](bb7179a8fd5ae80e049db41121e706c015e3ecf9))
- Resolve clippy warnings and compilation errors ([3ac1390](3ac1390fd872f9ee0ef3bddff4219042ac4ff78f))
- Gate chip_io module behind csca feature ([4e0ebae](4e0ebae179a59a70536302650b5b79c986457cf6))
- Update CI workflow for Python tests and feature testing ([1fb3f8e](1fb3f8e4219c3ec34b1f613867ee72ee82540844))
- Add placeholder Python tests and fix pytest path ([83f0aa8](83f0aa85b3d7c3b7b46b30d01721eec7c0b708c8))
- Gate testdata module behind test-fixtures feature ([94d069a](94d069a7ea9a391291b0f26951eeb0bcb851b208))
- Correct relative paths in testdata.rs for include_bytes ([9d26b61](9d26b614c2c94bed1460624e96ac22c751247608))
- Add CHANGELOG.md and fix git-cliff config path ([c9ab7c9](c9ab7c91d2ae87509a9487f884edb2c5205ee514))
- CI improvements - proper feature flags, Windows Python tests, remove MSRV matrix ([e08e449](e08e449565790481786e96131c3a50ae4c6c7bd7))
- Use bundled-sqlcipher-vendored-openssl for Windows compatibility ([0b8b558](0b8b5584d4569eba697852bfa16b834d75fbefce))

### Features

- Add automated release pipeline with RC staging ([475fca2](475fca2b5b579b011fe49a4b404c34afec7fd233))
- Add NIST PKITS test fixtures for certificate validation ([d9e050e](d9e050ec9a34e6a3ce1d65d819f7df513761f42d))
- Add Open Badges support and ZKP module ([b3cfb97](b3cfb9734c2ff3c614796e8b8f21215b18adc4d0))
- Add marty-bindings crate with PyO3 0.22 compatibility ([82321b3](82321b38ccf479c5f5eee472e1475ae0c5845dc1))

### Miscellaneous Tasks

- Update CHANGELOG.md ([1941514](194151407f6169e8d7b0befa56757bdb39fe5ed8))
- Update CHANGELOG.md ([629f286](629f28682954001551060c26936590b3fa3a94a5))
- Update CHANGELOG.md ([2135f22](2135f22bf7205dbb6f7d2f442186f339cbc8de1b))
- Update CHANGELOG.md ([df222cb](df222cbf44d07879525621acfc7d1c429ddff21e))

### Security

- Add comprehensive security and quality checks ([2826d48](2826d48a7d81d8943f77b8a40c6dfaa93b21950f))
- Make security checks non-blocking to prevent repeated failures ([b5c7091](b5c7091dd2c66c85b5bca0e1323d16d988c82218))

### Ci

- Enable all features including test-fixtures in CI ([fbc9ecd](fbc9ecdb373929b223b867a03d09b0b110e9a48a))

## [unreleased] - 2026-02-05

### Bug Fixes

- Auto-format code to pass CI checks ([bb7179a](bb7179a8fd5ae80e049db41121e706c015e3ecf9))
- Resolve clippy warnings and compilation errors ([3ac1390](3ac1390fd872f9ee0ef3bddff4219042ac4ff78f))
- Gate chip_io module behind csca feature ([4e0ebae](4e0ebae179a59a70536302650b5b79c986457cf6))
- Update CI workflow for Python tests and feature testing ([1fb3f8e](1fb3f8e4219c3ec34b1f613867ee72ee82540844))
- Add placeholder Python tests and fix pytest path ([83f0aa8](83f0aa85b3d7c3b7b46b30d01721eec7c0b708c8))
- Gate testdata module behind test-fixtures feature ([94d069a](94d069a7ea9a391291b0f26951eeb0bcb851b208))
- Correct relative paths in testdata.rs for include_bytes ([9d26b61](9d26b614c2c94bed1460624e96ac22c751247608))
- Add CHANGELOG.md and fix git-cliff config path ([c9ab7c9](c9ab7c91d2ae87509a9487f884edb2c5205ee514))
- CI improvements - proper feature flags, Windows Python tests, remove MSRV matrix ([e08e449](e08e449565790481786e96131c3a50ae4c6c7bd7))
- Use bundled-sqlcipher-vendored-openssl for Windows compatibility ([0b8b558](0b8b5584d4569eba697852bfa16b834d75fbefce))

### Features

- Add automated release pipeline with RC staging ([475fca2](475fca2b5b579b011fe49a4b404c34afec7fd233))
- Add NIST PKITS test fixtures for certificate validation ([d9e050e](d9e050ec9a34e6a3ce1d65d819f7df513761f42d))
- Add Open Badges support and ZKP module ([b3cfb97](b3cfb9734c2ff3c614796e8b8f21215b18adc4d0))
- Add marty-bindings crate with PyO3 0.22 compatibility ([82321b3](82321b38ccf479c5f5eee472e1475ae0c5845dc1))

### Miscellaneous Tasks

- Update CHANGELOG.md ([1941514](194151407f6169e8d7b0befa56757bdb39fe5ed8))
- Update CHANGELOG.md ([629f286](629f28682954001551060c26936590b3fa3a94a5))
- Update CHANGELOG.md ([2135f22](2135f22bf7205dbb6f7d2f442186f339cbc8de1b))

### Security

- Add comprehensive security and quality checks ([2826d48](2826d48a7d81d8943f77b8a40c6dfaa93b21950f))
- Make security checks non-blocking to prevent repeated failures ([b5c7091](b5c7091dd2c66c85b5bca0e1323d16d988c82218))

### Ci

- Enable all features including test-fixtures in CI ([fbc9ecd](fbc9ecdb373929b223b867a03d09b0b110e9a48a))

## [unreleased] - 2026-01-10

### Bug Fixes

- Auto-format code to pass CI checks ([bb7179a](bb7179a8fd5ae80e049db41121e706c015e3ecf9))
- Resolve clippy warnings and compilation errors ([3ac1390](3ac1390fd872f9ee0ef3bddff4219042ac4ff78f))
- Gate chip_io module behind csca feature ([4e0ebae](4e0ebae179a59a70536302650b5b79c986457cf6))
- Update CI workflow for Python tests and feature testing ([1fb3f8e](1fb3f8e4219c3ec34b1f613867ee72ee82540844))
- Add placeholder Python tests and fix pytest path ([83f0aa8](83f0aa85b3d7c3b7b46b30d01721eec7c0b708c8))
- Gate testdata module behind test-fixtures feature ([94d069a](94d069a7ea9a391291b0f26951eeb0bcb851b208))
- Correct relative paths in testdata.rs for include_bytes ([9d26b61](9d26b614c2c94bed1460624e96ac22c751247608))
- Add CHANGELOG.md and fix git-cliff config path ([c9ab7c9](c9ab7c91d2ae87509a9487f884edb2c5205ee514))
- CI improvements - proper feature flags, Windows Python tests, remove MSRV matrix ([e08e449](e08e449565790481786e96131c3a50ae4c6c7bd7))
- Use bundled-sqlcipher-vendored-openssl for Windows compatibility ([0b8b558](0b8b5584d4569eba697852bfa16b834d75fbefce))

### Features

- Add automated release pipeline with RC staging ([475fca2](475fca2b5b579b011fe49a4b404c34afec7fd233))
- Add NIST PKITS test fixtures for certificate validation ([d9e050e](d9e050ec9a34e6a3ce1d65d819f7df513761f42d))

### Miscellaneous Tasks

- Update CHANGELOG.md ([1941514](194151407f6169e8d7b0befa56757bdb39fe5ed8))
- Update CHANGELOG.md ([629f286](629f28682954001551060c26936590b3fa3a94a5))

### Security

- Add comprehensive security and quality checks ([2826d48](2826d48a7d81d8943f77b8a40c6dfaa93b21950f))

### Ci

- Enable all features including test-fixtures in CI ([fbc9ecd](fbc9ecdb373929b223b867a03d09b0b110e9a48a))

## [unreleased] - 2026-01-09

### Bug Fixes

- Auto-format code to pass CI checks ([bb7179a](bb7179a8fd5ae80e049db41121e706c015e3ecf9))
- Resolve clippy warnings and compilation errors ([3ac1390](3ac1390fd872f9ee0ef3bddff4219042ac4ff78f))
- Gate chip_io module behind csca feature ([4e0ebae](4e0ebae179a59a70536302650b5b79c986457cf6))
- Update CI workflow for Python tests and feature testing ([1fb3f8e](1fb3f8e4219c3ec34b1f613867ee72ee82540844))
- Add placeholder Python tests and fix pytest path ([83f0aa8](83f0aa85b3d7c3b7b46b30d01721eec7c0b708c8))
- Gate testdata module behind test-fixtures feature ([94d069a](94d069a7ea9a391291b0f26951eeb0bcb851b208))
- Correct relative paths in testdata.rs for include_bytes ([9d26b61](9d26b614c2c94bed1460624e96ac22c751247608))
- Add CHANGELOG.md and fix git-cliff config path ([c9ab7c9](c9ab7c91d2ae87509a9487f884edb2c5205ee514))
- CI improvements - proper feature flags, Windows Python tests, remove MSRV matrix ([e08e449](e08e449565790481786e96131c3a50ae4c6c7bd7))

### Features

- Add automated release pipeline with RC staging ([475fca2](475fca2b5b579b011fe49a4b404c34afec7fd233))
- Add NIST PKITS test fixtures for certificate validation ([d9e050e](d9e050ec9a34e6a3ce1d65d819f7df513761f42d))

### Miscellaneous Tasks

- Update CHANGELOG.md ([1941514](194151407f6169e8d7b0befa56757bdb39fe5ed8))

### Ci

- Enable all features including test-fixtures in CI ([fbc9ecd](fbc9ecdb373929b223b867a03d09b0b110e9a48a))

## [unreleased] - 2026-01-09

### Bug Fixes

- Auto-format code to pass CI checks ([bb7179a](bb7179a8fd5ae80e049db41121e706c015e3ecf9))
- Resolve clippy warnings and compilation errors ([3ac1390](3ac1390fd872f9ee0ef3bddff4219042ac4ff78f))
- Gate chip_io module behind csca feature ([4e0ebae](4e0ebae179a59a70536302650b5b79c986457cf6))
- Update CI workflow for Python tests and feature testing ([1fb3f8e](1fb3f8e4219c3ec34b1f613867ee72ee82540844))
- Add placeholder Python tests and fix pytest path ([83f0aa8](83f0aa85b3d7c3b7b46b30d01721eec7c0b708c8))
- Gate testdata module behind test-fixtures feature ([94d069a](94d069a7ea9a391291b0f26951eeb0bcb851b208))
- Correct relative paths in testdata.rs for include_bytes ([9d26b61](9d26b614c2c94bed1460624e96ac22c751247608))
- Add CHANGELOG.md and fix git-cliff config path ([c9ab7c9](c9ab7c91d2ae87509a9487f884edb2c5205ee514))

### Features

- Add automated release pipeline with RC staging ([475fca2](475fca2b5b579b011fe49a4b404c34afec7fd233))
- Add NIST PKITS test fixtures for certificate validation ([d9e050e](d9e050ec9a34e6a3ce1d65d819f7df513761f42d))

### Ci

- Enable all features including test-fixtures in CI ([fbc9ecd](fbc9ecdb373929b223b867a03d09b0b110e9a48a))

<!-- git-cliff will insert new entries here -->

