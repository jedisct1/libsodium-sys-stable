//! Minimal WAI guest module for libsodium
//!
//! This example compiles to a wasm module that exports the WAI interface.
//! The actual WAI implementation is in src/wai_component.rs.
//!
//! Build: cargo build --example wasmer_wai_test --target wasm32-wasip1 --features wasmer-wai --release
//! Run:   wasmer run target/wasm32-wasip1/release/examples/wasmer_wai_test.wasm
//!
//! The exported WAI functions can be called from a host using wai-bindgen-wasmer.

fn main() {
    println!("libsodium WAI module loaded");

    // The WAI interface is automatically exported by the library.
    // This main function is optional - the wasm can be used as a library.
    //
    // Use `wasmer inspect <wasm>` to see the exported WAI functions:
    //   - init, version-string, library-version-major, library-version-minor
    //   - random-bytes, random-u32, random-uniform
    //   - secretbox-*, box-*, seal-*, sign-*
    //   - generichash-*, sha256, sha512
    //   - auth-*, aead-xchacha20poly1305-*
    //   - kdf-*, pwhash-*
    //   - bin2hex, hex2bin, bin2base64, base642bin, verify32
}
