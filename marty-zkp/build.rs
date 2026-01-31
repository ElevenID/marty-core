//! Build script for marty-zkp
//!
//! This script compiles the LibZK C++ library using CMake and links it
//! for FFI consumption by the Rust crate.

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=src/cpp/");
    println!("cargo:rerun-if-env-changed=LIBZK_PATH");

    // Determine LibZK source path
    let libzk_path = env::var("LIBZK_PATH").unwrap_or_else(|_| {
        // Default: assume longfellow-zk is cloned alongside marty-core
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        let workspace_root = PathBuf::from(&manifest_dir)
            .parent() // marty-core
            .and_then(|p| p.parent()) // work directory
            .map(|p| p.join("longfellow-zk"))
            .unwrap_or_else(|| PathBuf::from("../../../longfellow-zk"));
        workspace_root.to_string_lossy().to_string()
    });

    let libzk_path = PathBuf::from(&libzk_path);

    // Check if we should use the real LibZK or fall back to mock
    let use_mock = env::var("USE_ZK_MOCK").unwrap_or_else(|_| "1".to_string()) == "1";

    if use_mock || !libzk_path.join("lib").exists() {
        // Compile mock implementation
        println!("cargo:warning=Using mock ZK implementation");
        compile_mock();
    } else {
        // Compile real LibZK via CMake
        compile_libzk(&libzk_path);
    }
}

fn compile_mock() {
    let mock_source = "src/cpp/zk_mock.cpp";
    
    if std::path::Path::new(mock_source).exists() {
        cc::Build::new()
            .cpp(true)
            .file(mock_source)
            .flag_if_supported("-std=c++17")
            .compile("zk_mock");
        
        println!("cargo:rustc-link-lib=static=zk_mock");
    } else {
        println!("cargo:warning=Mock source not found, ZK functions will be stubs");
    }
}

fn compile_libzk(libzk_path: &PathBuf) {
    let lib_dir = libzk_path.join("lib");
    
    // Use cmake crate to build LibZK
    let dst = cmake::Config::new(&lib_dir)
        .define("CMAKE_BUILD_TYPE", "Release")
        .define("BUILD_TESTING", "OFF")
        .build();

    // Link the built library
    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    println!("cargo:rustc-link-lib=static=zk");
    
    // Link C++ standard library
    #[cfg(target_os = "macos")]
    println!("cargo:rustc-link-lib=c++");
    
    #[cfg(target_os = "linux")]
    println!("cargo:rustc-link-lib=stdc++");
    
    // Link OpenSSL (required by LibZK)
    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");
}
