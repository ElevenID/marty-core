//! Build script for marty-zkp
//!
//! **Real library (default):** compiles 12 Longfellow source files directly.
//!
//! **Mock stub (dev / CI only):** activated by either:
//!   - the `zk-mock` Cargo feature  (`--features marty-zkp/zk-mock`), or
//!   - the environment variable `USE_ZK_MOCK=1` (convenience alias).
//!
//! Building with `--release` while the mock is active is a **hard compile
//! error** — the mock must never make it into a production binary.

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=src/cpp/");
    println!("cargo:rerun-if-env-changed=LIBZK_PATH");
    println!("cargo:rerun-if-env-changed=USE_ZK_MOCK");
    println!("cargo::rustc-check-cfg=cfg(zk_mock)");

    // Mock is active when the Cargo feature is set OR the env-var shortcut is used.
    let feature_active = env::var("CARGO_FEATURE_ZK_MOCK").is_ok();
    let env_active = env::var("USE_ZK_MOCK").unwrap_or_default() == "1";
    let use_mock = feature_active || env_active;

    if use_mock {
        let profile = env::var("PROFILE").unwrap_or_default();
        if profile == "release" {
            // Hard error — stops the build immediately.
            eprintln!(
                "cargo:error=ZK mock (feature \"zk-mock\" or USE_ZK_MOCK=1) \
                 must NOT be used in release builds. \
                 Remove --features marty-zkp/zk-mock and unset USE_ZK_MOCK."
            );
            std::process::exit(1);
        }
        // Expose cfg(zk_mock) so Rust source can gate on it (belt-and-suspenders).
        println!("cargo:rustc-cfg=zk_mock");
        compile_mock();
        return;
    }

    let libzk_path = env::var("LIBZK_PATH").unwrap_or_else(|_| {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        let workspace_root = PathBuf::from(&manifest_dir)
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join("longfellow-zk"))
            .unwrap_or_else(|| PathBuf::from("../../../longfellow-zk"));
        workspace_root.to_string_lossy().to_string()
    });
    compile_libzk(&PathBuf::from(libzk_path));
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
        // Suppress warnings from vendored longfellow-zk library
        .flag("-Wno-unused-parameter")
        .flag("-Wno-missing-field-initializers")
        .flag("-Wno-sign-compare")
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
