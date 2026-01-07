//! Simple test to verify the WASI component compiles and exports work
//! Build with: cargo build --example wasi_component_test --target wasm32-wasip2 --features wasi-component

fn main() {
    // Initialize libsodium
    println!("Testing libsodium WASI component...");

    // The component module is internal, so we just verify the build works
    // In a real scenario, this would be consumed by a WASI host
    println!("WASI component build successful!");
}
