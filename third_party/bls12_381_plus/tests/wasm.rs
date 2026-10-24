#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::*;

// #[cfg(test)]
#[wasm_bindgen_test]
fn wasm_scalar_tests() {
    bls12_381_plus::run_test_wasm();
}
