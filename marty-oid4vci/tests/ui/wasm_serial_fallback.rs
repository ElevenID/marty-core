//! Compile-only probe for `scripts/test_oid4vci_wasm_serial_fallback.sh`.
//!
//! This probe never executes in a browser or WASM runtime. The first compilation
//! shows that a browser-WASM consumer can reach the public serial batch entry
//! point. The script compiles this file a second time with the private
//! `cdla_native_worker_probe` cfg and requires these native-only imports to fail.

use marty_oid4vci::signing_batch::Es256SignerScope;

#[cfg(cdla_native_worker_probe)]
use marty_oid4vci::signing_batch::{
    BoundedConcurrentCredentialSigner, ConcurrentEs256SignerScope, MAX_CONCURRENT_SIGNING_WORKERS,
};

pub fn serial_sign_batch_is_available_on_wasm(scope: &Es256SignerScope<'_>) {
    let _outcome = scope.sign_batch(Vec::new());
}
