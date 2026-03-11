//! Build script for marty-zkp
//!
//! When USE_ZK_MOCK=1, compiles the mock C++ stub.
//! Otherwise (default), compiles the real Longfellow ZK library sources
//! directly using the `cc` crate — no CMake required.

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=src/cpp/");
    println!("cargo:rerun-if-env-changed=LIBZK_PATH");
    println!("cargo:rerun-if-env-changed=USE_ZK_MOCK");

    let libzk_path = env::var("LIBZK_PATH").unwrap_or_else(|_| {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        let workspace_root = PathBuf::from(&manifest_dir)
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join("longfellow-zk"))
            .unwrap_or_else(|| PathBuf::from("../../../longfellow-zk"));
        workspace_root.to_string_lossy().to_string()
    });

    let libzk_path = PathBuf::from(&libzk_path);

    let use_mock = env::var("USE_ZK_MOCK").unwrap_or_else(|_| "0".to_string());
    if use_mock == "1" {
        compile_mock();
    } else {
        compile_libzk(&libzk_path);
    }
}

fn compile_mock() {
    cc::Build::new()
        .cpp(true)
        .file("src/cpp/zk_mock.cpp")
        .flag_if_supported("-std=c++17")
        .compile("zk_mock");
}

fn compile_libzk(lib_dir: &std::path::Path) {
    let lib_src = lib_dir.join("lib");

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    let mut build = cc::Build::new();
    build
        .cpp(true)
        .flag("-std=c++17")
        .flag("-O2")
        .flag("-DOPENSSL_SUPPRESS_DEPRECATED=1")
        .include(&lib_src);

    // Architecture-specific crypto acceleration flags
    if target_arch == "aarch64" {
        build.flag("-march=armv8-a+crypto");
    } else if target_arch == "x86_64" {
        build.flag("-mpclmul");
    }

    // macOS: Homebrew OpenSSL and zstd headers
    if target_os == "macos" {
        build.include("/opt/homebrew/include");
    }

    build
        .file(lib_src.join("circuits/mdoc/mdoc_zk.cc"))
        .file(lib_src.join("circuits/mdoc/mdoc_decompress.cc"))
        .file(lib_src.join("circuits/mdoc/mdoc_generate_circuit.cc"))
        .file(lib_src.join("circuits/mdoc/mdoc_circuit_id.cc"))
        .file(lib_src.join("circuits/mdoc/zk_spec.cc"))
        .file(lib_src.join("circuits/sha/flatsha256_witness.cc"))
        .file(lib_src.join("circuits/sha/sha256_constants.cc"))
        .file(lib_src.join("ec/p256.cc"))
        .file(lib_src.join("algebra/nat.cc"))
        .file(lib_src.join("algebra/crt.cc"))
        .file(lib_src.join("util/log.cc"))
        .file(lib_src.join("util/crypto.cc"))
        .compile("longfellow_zk");

    if target_os == "macos" {
        println!("cargo:rustc-link-search=/opt/homebrew/lib");
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
    }

    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rustc-link-lib=zstd");
}