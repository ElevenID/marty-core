Open Badges interop fixtures

These JSON files are deterministic verify requests used by the Rust interop tests.

Regenerate:
- `cargo run --example generate_open_badges_fixtures` from `rust/marty-verification`

Env overrides:
- `OPEN_BADGES_OB2_VERIFY_REQUEST`
- `OPEN_BADGES_OB3_VERIFY_REQUEST`
