# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.10] - 2026-07-21

### Bug Fixes

- Encode ISO 18013-5 full-date claims with RFC 8943 CBOR tag 1004 while retaining tag 0 for RFC 3339 date-times.

### CI

- Enforce append-only release metadata and Cargo-derived Python package versions.

## [0.1.2] - 2026-07-17

### Bug Fixes

- **release**: Install OpenSSL for Linux wheels ([322bd19](322bd1937481fb2e6ef106ad9033692e49c46245))
- **release**: Install OpenSSL Perl build support ([5375d05](5375d057d08d155f5cdd19749a315b515af28f43))
- **release**: Install complete OpenSSL Perl toolchain ([70bb2cf](70bb2cfb588f75a2d39d1bc89179f789502342f4))
- **release**: Build portable Python extension wheels ([3899ffa](3899ffa8ec8e37c0d851bc5610ddbc07a436a7c5))
- **release**: Use Rustls for portable Linux wheels ([51cff7c](51cff7c4b10ae848353455cf108a161126585248))

## [0.1.1] - 2026-07-17

### Bug Fixes

- Restore LTI claim tests for core release ([c224db6](c224db6f7ccc574aa5ca63edae57c311f7a2ac70))

### Styling

- Format LTI claim constants ([5bb833f](5bb833fd4681d062ef6dbb37fda3245f08b5e2fa))

### Ci

- Use license-free publication secret scan ([fc67dac](fc67dacbf3ed093148f672b013ebe5c0d2cae452))

## [0.1.0] - 2026-07-17

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
- Make MIP release checks hermetic ([418b6d9](418b6d940ae72cdd93eda2cc8ba283062c24d04d))
- Clear remaining core CI blockers ([f60e675](f60e675f8f303a38ee84cc8e5bee88c5efae5a0c))
- Stabilize cross-platform core checks ([7f2db11](7f2db117f6d88e848073c54215ae4a71d3b68abb))
- Satisfy Rust 1.97 ISO clippy ([cef6e7a](cef6e7a028181fa7e046dc517150d1556feec8b9))
- Keep PyO3 bindings clean on Rust 1.97 ([e155ee5](e155ee515ae1162298e5826acd54a6485d612109))
- Repair remaining feature matrix checks ([1ea132b](1ea132bd1c9ea5b30974ee5588fad7b41d8e804b))

### Features

- Add automated release pipeline with RC staging ([475fca2](475fca2b5b579b011fe49a4b404c34afec7fd233))
- Add NIST PKITS test fixtures for certificate validation ([d9e050e](d9e050ec9a34e6a3ce1d65d819f7df513761f42d))
- Add Open Badges support and ZKP module ([b3cfb97](b3cfb9734c2ff3c614796e8b8f21215b18adc4d0))
- Add marty-bindings crate with PyO3 0.22 compatibility ([82321b3](82321b38ccf479c5f5eee472e1475ae0c5845dc1))
- **oid4vci**: Add OID4VCI module and update ZKP mock implementation ([beda752](beda752f039a674a03cfe19e02d53a804139fb52))
- **marty-zkp**: Replace mock with real Longfellow ZK C API ([117d1be](117d1bead0c14ca783ade1101393f285d90f2e21))
- **oid4vci,verification**: Add OID4VCI verifier, SD-JWT VC support, and CAVP/conformance test suites ([e130a0a](e130a0ae306a842d7bda05a052fa124d9931a6c4))
- GRPC migration, Cedar authorization, BBS crypto, OID4VC conformance, and service layer enhancements ([025cefb](025cefb5fc69d03b68e589231c66be1c6cd3c213))
- Add vds-nc and lti support to oid4vci ([76eb3f9](76eb3f9081fd80e1218d9906ebc5780a20da5556))
- Add MIP release browser wallet ([d4bbfb9](d4bbfb9c3093efff719ba405ef58667b3f826fd8))
- Adopt OID4VCI Final nonce flow ([6144276](6144276fac4abd4172d7d481a191d87e1cbeacc7))

### Miscellaneous Tasks

- Commit generated types for git dep compatibility ([b375db3](b375db36900347f139679feebdb3490ae466ee41))
- Sync working state for dev environment migration ([1d65c9c](1d65c9c981bab956ff1bf73a3a40f83454d78be8))
- Prepare for automated improvements ([56288cc](56288cc3488af80b9a4c2f08b3535033d09b6e71))

### Security

- Add comprehensive security and quality checks ([2826d48](2826d48a7d81d8943f77b8a40c6dfaa93b21950f))
- Make security checks non-blocking to prevent repeated failures ([b5c7091](b5c7091dd2c66c85b5bca0e1323d16d988c82218))

### Testing

- **marty-zkp**: Multi-attribute coverage + attribute count validation ([0050122](005012210c90ad863855e633dfbc2b5336ffed98))

### Ci

- Enable all features including test-fixtures in CI ([fbc9ecd](fbc9ecdb373929b223b867a03d09b0b110e9a48a))
- Add repository_dispatch to notify downstream repos on release ([f21287e](f21287e22a1f7d7ac53112dc4aabe6f18f538de7))
- Use REPO_ACCESS_TOKEN for cross-repo dispatch ([438d0f8](438d0f817b6f6c5e19827045d92d4bf28280eb99))
- Remove stale vendored core gate ([cf8cae7](cf8cae7a2a955074429353cf65e4496882b83fd7))

### Security

- **marty-zkp**: Hard-block ZK mock from release builds ([53c2d35](53c2d354f56c980c9595fac0f98e064e46e576ed))

<!-- generated by git-cliff -->
