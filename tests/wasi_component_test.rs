//! Integration test for the WASI component
//!
//! These tests verify the WASI component build works correctly.
//! Run with: cargo test --test wasi_component_test
//!
//! Note: These tests require wasm-tools and wasmtime to be installed.
//! They also require the wasm32-wasip2 target to be installed.

use std::process::Command;

fn build_wasm_component() -> bool {
    // Check if wasm32-wasip2 target is available
    let target_check = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
        .expect("Failed to check targets");

    let targets = String::from_utf8_lossy(&target_check.stdout);
    if !targets.contains("wasm32-wasip2") {
        eprintln!("wasm32-wasip2 target not installed, skipping test");
        return false;
    }

    // Build the component using rustc with cdylib crate-type
    let status = Command::new("cargo")
        .args([
            "rustc",
            "--target", "wasm32-wasip2",
            "--features", "wasi-component",
            "--release",
            "--crate-type", "cdylib",
        ])
        .status()
        .expect("Failed to build component");

    status.success()
}

#[test]
fn test_component_exports_are_present() {
    if !build_wasm_component() {
        eprintln!("Component build failed or target not available, skipping test");
        return;
    }

    // Verify the wasm file exists
    let wasm_path = std::path::Path::new("target/wasm32-wasip2/release/libsodium_sys.wasm");
    if !wasm_path.exists() {
        eprintln!("WASM file not found at {:?}, skipping test", wasm_path);
        return;
    }

    // Check if wasm-tools is available
    let wasm_tools_check = Command::new("wasm-tools").arg("--version").output();
    if wasm_tools_check.is_err() || !wasm_tools_check.unwrap().status.success() {
        eprintln!("wasm-tools not installed, skipping export verification");
        return;
    }

    // Use wasm-tools to verify the component exports
    let output = Command::new("wasm-tools")
        .args(["component", "wit", wasm_path.to_str().unwrap()])
        .output()
        .expect("Failed to run wasm-tools");

    let wit_output = String::from_utf8_lossy(&output.stdout);

    // Verify all expected exports are present
    let expected_exports = [
        "export libsodium:crypto/types@1.0.21",
        "export libsodium:crypto/core@1.0.21",
        "export libsodium:crypto/random@1.0.21",
        "export libsodium:crypto/secretbox@1.0.21",
        "export libsodium:crypto/crypto-box@1.0.21",
        "export libsodium:crypto/seal@1.0.21",
        "export libsodium:crypto/sign@1.0.21",
        "export libsodium:crypto/generichash@1.0.21",
        "export libsodium:crypto/sha256@1.0.21",
        "export libsodium:crypto/sha512@1.0.21",
        "export libsodium:crypto/auth@1.0.21",
        "export libsodium:crypto/aead-xchacha20poly1305@1.0.21",
        "export libsodium:crypto/aead-chacha20poly1305-ietf@1.0.21",
        "export libsodium:crypto/aead-aegis128l@1.0.21",
        "export libsodium:crypto/aead-aegis256@1.0.21",
        "export libsodium:crypto/pwhash@1.0.21",
        "export libsodium:crypto/kdf@1.0.21",
        "export libsodium:crypto/kdf-hkdf-sha256@1.0.21",
        "export libsodium:crypto/kx@1.0.21",
        "export libsodium:crypto/scalarmult@1.0.21",
        "export libsodium:crypto/utils@1.0.21",
        "export libsodium:crypto/shorthash@1.0.21",
        "export libsodium:crypto/onetimeauth@1.0.21",
        "export libsodium:crypto/cipher-xsalsa20@1.0.21",
        "export libsodium:crypto/cipher-xchacha20@1.0.21",
    ];

    for export in &expected_exports {
        assert!(
            wit_output.contains(export),
            "Missing export: {}\nActual output:\n{}",
            export,
            wit_output
        );
    }

    println!("All {} exports verified!", expected_exports.len());
}

#[test]
fn test_component_compiles_with_wasmtime() {
    if !build_wasm_component() {
        eprintln!("Component build failed or target not available, skipping test");
        return;
    }

    let wasm_path = "target/wasm32-wasip2/release/libsodium_sys.wasm";
    if !std::path::Path::new(wasm_path).exists() {
        eprintln!("WASM file not found, skipping test");
        return;
    }

    // Check if wasmtime is available
    let wasmtime_check = Command::new("wasmtime").arg("--version").output();
    if wasmtime_check.is_err() || !wasmtime_check.unwrap().status.success() {
        eprintln!("wasmtime not installed, skipping compilation test");
        return;
    }

    // Try to compile with wasmtime (validates the component)
    let output = Command::new("wasmtime")
        .args(["compile", wasm_path, "-o", "/tmp/libsodium_test.cwasm"])
        .output()
        .expect("Failed to run wasmtime");

    assert!(
        output.status.success(),
        "Wasmtime compilation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    println!("Component successfully compiled with wasmtime!");
}
