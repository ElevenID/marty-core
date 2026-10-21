# Engine vector ownership

These three public vectors belong to `tests/oid4vp_conformance.rs`. They remain
inside this crate for hermetic package testing. `static_fixture_vp_token_verifies`
checks the pinned VP signature, audience and nonce. Dynamic signing cases use
the existing disposable OpenBao helper; do not restore a checked-in private seed
or Python generator to refresh signed vectors.

Verifier owns adapter-level vectors; Authenticator owns wallet request/parser
vectors. The current parsed definition/submission and trimmed public VP token
match Verifier's; package-local copies keep tests hermetic. Review
format, signature and expected engine behavior when changing these files; do not
bulk regenerate other repositories or claim official OIDF conformance from them.

Integration's unused historical generator and corpus are retired. The native
engine and consumer suites remain the executable owners of their requirements.
